// BRY-NFET-SX Vault — client-side encryption logic
//
// NO LOGGING — any console.log of a password, plaintext, or derived key is a
// bug. Do not add diagnostic logs of user data even temporarily.
//
// All cryptography runs in this tab via libsodium.js (see sodium.js).
// Plaintext never leaves the browser. There are zero network requests after
// the page loads (enforced by Content-Security-Policy connect-src 'none').
//
// VAULT FORMAT V2 (default for new encryptions):
//   {
//     "schema":     "BRY-NFET-SX-VAULT-V2",
//     "version":    "0.28.1",
//     "created_at": "<iso>",
//     "mode":       "self" | "share",
//     "kdf": {
//       "algorithm": "argon2id",
//       "opslimit":  4,
//       "memlimit":  100663296,
//       "salt":      "<b64url, 16 bytes>"
//     },
//     "wrap": {
//       "algorithm":   "XChaCha20-Poly1305",
//       "nonce":       "<b64url, 24 bytes>",
//       "wrapped_key": "<b64url, 48 bytes (32-byte vault_key + 16-byte tag)>"
//     },
//     "content": {
//       "algorithm":  "XChaCha20-Poly1305",
//       "nonce":      "<b64url, 24 bytes>",
//       "ciphertext": "<b64url>"
//     }
//   }
//
// V2 separates the DATA encryption key from the PASSWORD-derived key:
//   1. A fresh random 32-byte `vault_key` is generated for every vault.
//   2. The password is stretched by Argon2id into a `wrap_key`.
//   3. `wrap_key` wraps `vault_key` via XChaCha20-Poly1305 (wrap_nonce + AAD).
//   4. `vault_key` encrypts the plaintext via XChaCha20-Poly1305
//      (content_nonce + SAME AAD).
//   5. On decrypt: derive wrap_key → unwrap vault_key → decrypt content.
//
// Why this matters: the password's role is demoted from "the entire vault
// secrecy key" to "one unlock path for the data key." Today there is still
// only one unlock path (the password). The format change is the primitive
// you need before you could ever add a second unlock path (recovery code,
// device-bound key, etc.) without re-encrypting the data.
//
// Legacy V1 vaults are still readable. V1 encryption is NOT performed for
// new vaults; it exists only to keep old boxes openable and to run a V1
// round-trip self-test at page load.
//
// AAD is NOT stored. It is derived deterministically on both encrypt and
// decrypt by canonical-JSON-serializing the full metadata block. The SAME
// AAD is used for both wrap and content AEAD operations, so tampering with
// any bound field breaks at least one of them.

(function () {
  "use strict";

  // -------- Constants --------
  const SCHEMA_V1 = "BRY-NFET-SX-VAULT-V1";
  const SCHEMA_V2 = "BRY-NFET-SX-VAULT-V2";
  // Qira Notify envelope — structurally similar to V2 but with
  // literal `wrap.aad` / `content.aad` domain strings as AAD (not
  // a canonical-JSON-derived binding). Accepted here for read-only
  // decryption so a Notify JSON + phrase opens in the Vault tab.
  const SCHEMA_QIRA_NOTIFY_V1 = "QIRA-NOTIFY-V1";
  const SCHEMA = SCHEMA_V2; // default schema for new encryptions
  const VERSION = "0.28.1";
  const KDF_ALG = "argon2id";
  const AEAD_ALG = "XChaCha20-Poly1305";
  const DEFAULT_OPSLIMIT = 4;
  const DEFAULT_MEMLIMIT = 96 * 1024 * 1024;
  const MIN_OPSLIMIT = 1;
  const MAX_OPSLIMIT = 10;
  const MIN_MEMLIMIT = 8 * 1024 * 1024;
  const MAX_MEMLIMIT = 256 * 1024 * 1024;
  const SALT_BYTES = 16;
  const NONCE_BYTES = 24;
  const KEY_BYTES = 32;
  const MAX_PLAINTEXT_BYTES = 256 * 1024;
  const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
  const VAULT_TEXT_PREFIX_V1 = "BRY-VAULT-V1.";
  const VAULT_TEXT_PREFIX_V2 = "BRY-VAULT-V2.";
  // Password-strength gate: submit is blocked until the live strength score
  // meets this threshold. 3 on a 0-7 scale corresponds roughly to "okay"
  // (~12+ chars or a 4-word phrase). Weak single-word inputs fall below it.
  const MIN_STRENGTH_SCORE = 3;

  // Lock strength presets. Stronger = longer to lock/unlock, but linearly
  // more expensive for an offline brute-force attacker per password guess.
  //
  // Strong-lock was bumped in v0.28.1-phrase1 from opslimit=3/64 MiB (~2s)
  // to opslimit=4/96 MiB (~4s). Double the cost, double the attacker's
  // offline brute-force time, negligible UX impact for legitimate users
  // who unlock at most a few times per session.
  const LOCK_PRESETS = {
    quick:  { opslimit: 1, memlimit: 32  * 1024 * 1024, label: "Quick lock",  hint: "about 1 second"  },
    strong: { opslimit: 4, memlimit: 96  * 1024 * 1024, label: "Strong lock", hint: "about 4 seconds" },
    vault:  { opslimit: 6, memlimit: 128 * 1024 * 1024, label: "Vault lock",  hint: "about 7 seconds" },
  };
  const DEFAULT_PRESET_KEY = "strong";

  // Wordlist for the passphrase generator: the EFF long wordlist, 7776
  // words (7776 = 6^5, so the list is also dice-compatible). The only four
  // hyphenated EFF entries are replaced with unhyphenated equivalents
  // (drop-down -> dropdown, felt-tip -> felttip, t-shirt -> tshirt,
  // yo-yo -> yoyoing) because the generated phrase joins words with "-".
  //
  // 4 words = log2(7776^4) ~= 51.7 bits, and the 2 appended digits add
  // log2(100) ~= 6.6 bits, for about 58 bits total. Word and digit indices
  // both come from sodium.randombytes_uniform, which is unbiased.
  //
  // This list MUST stay byte-identical to PASSPHRASE_WORDS in
  // qev-cli/lib/vault.js and tauri-app/ui/chat.js. It is used ONLY by
  // generatePassphrase() — never by an encrypt or decrypt path — so
  // changing it cannot affect vaults that already exist. The phrase is
  // user-supplied input; the vault format, KDF parameters, and AEAD are
  // untouched.
  const PASSPHRASE_WORDS = (
    "abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion " +
    "abrasive abreast abridge abroad abruptly absence absentee absently absinthe absolute " +
    "absolve abstain abstract absurd accent acclaim acclimate accompany account accuracy " +
    "accurate accustom acetone achiness aching acid acorn acquaint acquire acre " +
    "acrobat acronym acting action activate activator active activism activist activity " +
    "actress acts acutely acuteness aeration aerobics aerosol aerospace afar affair " +
    "affected affecting affection affidavit affiliate affirm affix afflicted affluent afford " +
    "affront aflame afloat aflutter afoot afraid afterglow afterlife aftermath aftermost " +
    "afternoon aged ageless agency agenda agent aggregate aghast agile agility " +
    "aging agnostic agonize agonizing agony agreeable agreeably agreed agreeing agreement " +
    "aground ahead ahoy aide aids aim ajar alabaster alarm albatross " +
    "album alfalfa algebra algorithm alias alibi alienable alienate aliens alike " +
    "alive alkaline alkalize almanac almighty almost aloe aloft aloha alone " +
    "alongside aloof alphabet alright although altitude alto aluminum alumni always " +
    "amaretto amaze amazingly amber ambiance ambiguity ambiguous ambition ambitious ambulance " +
    "ambush amendable amendment amends amenity amiable amicably amid amigo amino " +
    "amiss ammonia ammonium amnesty amniotic among amount amperage ample amplifier " +
    "amplify amply amuck amulet amusable amused amusement amuser amusing anaconda " +
    "anaerobic anagram anatomist anatomy anchor anchovy ancient android anemia anemic " +
    "aneurism anew angelfish angelic anger angled angler angles angling angrily " +
    "angriness anguished angular animal animate animating animation animator anime animosity " +
    "ankle annex annotate announcer annoying annually annuity anointer another answering " +
    "antacid antarctic anteater antelope antennae anthem anthill anthology antibody antics " +
    "antidote antihero antiquely antiques antiquity antirust antitoxic antitrust antiviral antivirus " +
    "antler antonym antsy anvil anybody anyhow anymore anyone anyplace anything " +
    "anytime anyway anywhere aorta apache apostle appealing appear appease appeasing " +
    "appendage appendix appetite appetizer applaud applause apple appliance applicant applied " +
    "apply appointee appraisal appraiser apprehend approach approval approve apricot april " +
    "apron aptitude aptly aqua aqueduct arbitrary arbitrate ardently area arena " +
    "arguable arguably argue arise armadillo armband armchair armed armful armhole " +
    "arming armless armoire armored armory armrest army aroma arose around " +
    "arousal arrange array arrest arrival arrive arrogance arrogant arson art " +
    "ascend ascension ascent ascertain ashamed ashen ashes ashy aside askew " +
    "asleep asparagus aspect aspirate aspire aspirin astonish astound astride astrology " +
    "astronaut astronomy astute atlantic atlas atom atonable atop atrium atrocious " +
    "atrophy attach attain attempt attendant attendee attention attentive attest attic " +
    "attire attitude attractor attribute atypical auction audacious audacity audible audibly " +
    "audience audio audition augmented august authentic author autism autistic autograph " +
    "automaker automated automatic autopilot available avalanche avatar avenge avenging avenue " +
    "average aversion avert aviation aviator avid avoid await awaken award " +
    "aware awhile awkward awning awoke awry axis babble babbling babied " +
    "baboon backache backboard backboned backdrop backed backer backfield backfire backhand " +
    "backing backlands backlash backless backlight backlit backlog backpack backpedal backrest " +
    "backroom backshift backside backslid backspace backspin backstab backstage backtalk backtrack " +
    "backup backward backwash backwater backyard bacon bacteria bacterium badass badge " +
    "badland badly badness baffle baffling bagel bagful baggage bagged baggie " +
    "bagginess bagging baggy bagpipe baguette baked bakery bakeshop baking balance " +
    "balancing balcony balmy balsamic bamboo banana banish banister banjo bankable " +
    "bankbook banked banker banking banknote bankroll banner bannister banshee banter " +
    "barbecue barbed barbell barber barcode barge bargraph barista baritone barley " +
    "barmaid barman barn barometer barrack barracuda barrel barrette barricade barrier " +
    "barstool bartender barterer bash basically basics basil basin basis basket " +
    "batboy batch bath baton bats battalion battered battering battery batting " +
    "battle bauble bazooka blabber bladder blade blah blame blaming blanching " +
    "blandness blank blaspheme blasphemy blast blatancy blatantly blazer blazing bleach " +
    "bleak bleep blemish blend bless blighted blimp bling blinked blinker " +
    "blinking blinks blip blissful blitz blizzard bloated bloating blob blog " +
    "bloomers blooming blooper blot blouse blubber bluff bluish blunderer blunt " +
    "blurb blurred blurry blurt blush blustery boaster boastful boasting boat " +
    "bobbed bobbing bobble bobcat bobsled bobtail bodacious body bogged boggle " +
    "bogus boil bok bolster bolt bonanza bonded bonding bondless boned " +
    "bonehead boneless bonelike boney bonfire bonnet bonsai bonus bony boogeyman " +
    "boogieman book boondocks booted booth bootie booting bootlace bootleg boots " +
    "boozy borax boring borough borrower borrowing boss botanical botanist botany " +
    "botch both bottle bottling bottom bounce bouncing bouncy bounding boundless " +
    "bountiful bovine boxcar boxer boxing boxlike boxy breach breath breeches " +
    "breeching breeder breeding breeze breezy brethren brewery brewing briar bribe " +
    "brick bride bridged brigade bright brilliant brim bring brink brisket " +
    "briskly briskness bristle brittle broadband broadcast broaden broadly broadness broadside " +
    "broadways broiler broiling broken broker bronchial bronco bronze bronzing brook " +
    "broom brought browbeat brownnose browse browsing bruising brunch brunette brunt " +
    "brush brussels brute brutishly bubble bubbling bubbly buccaneer bucked bucket " +
    "buckle buckshot buckskin bucktooth buckwheat buddhism buddhist budding buddy budget " +
    "buffalo buffed buffer buffing buffoon buggy bulb bulge bulginess bulgur " +
    "bulk bulldog bulldozer bullfight bullfrog bullhorn bullion bullish bullpen bullring " +
    "bullseye bullwhip bully bunch bundle bungee bunion bunkbed bunkhouse bunkmate " +
    "bunny bunt busboy bush busily busload bust busybody buzz cabana " +
    "cabbage cabbie cabdriver cable caboose cache cackle cacti cactus caddie " +
    "caddy cadet cadillac cadmium cage cahoots cake calamari calamity calcium " +
    "calculate calculus caliber calibrate calm caloric calorie calzone camcorder cameo " +
    "camera camisole camper campfire camping campsite campus canal canary cancel " +
    "candied candle candy cane canine canister cannabis canned canning cannon " +
    "cannot canola canon canopener canopy canteen canyon capable capably capacity " +
    "cape capillary capital capitol capped capricorn capsize capsule caption captivate " +
    "captive captivity capture caramel carat caravan carbon cardboard carded cardiac " +
    "cardigan cardinal cardstock carefully caregiver careless caress caretaker cargo caring " +
    "carless carload carmaker carnage carnation carnival carnivore carol carpenter carpentry " +
    "carpool carport carried carrot carrousel carry cartel cartload carton cartoon " +
    "cartridge cartwheel carve carving carwash cascade case cash casing casino " +
    "casket cassette casually casualty catacomb catalog catalyst catalyze catapult cataract " +
    "catatonic catcall catchable catcher catching catchy caterer catering catfight catfish " +
    "cathedral cathouse catlike catnap catnip catsup cattail cattishly cattle catty " +
    "catwalk caucasian caucus causal causation cause causing cauterize caution cautious " +
    "cavalier cavalry caviar cavity cedar celery celestial celibacy celibate celtic " +
    "cement census ceramics ceremony certainly certainty certified certify cesarean cesspool " +
    "chafe chaffing chain chair chalice challenge chamber chamomile champion chance " +
    "change channel chant chaos chaperone chaplain chapped chaps chapter character " +
    "charbroil charcoal charger charging chariot charity charm charred charter charting " +
    "chase chasing chaste chastise chastity chatroom chatter chatting chatty cheating " +
    "cheddar cheek cheer cheese cheesy chef chemicals chemist chemo cherisher " +
    "cherub chess chest chevron chevy chewable chewer chewing chewy chief " +
    "chihuahua childcare childhood childish childless childlike chili chill chimp chip " +
    "chirping chirpy chitchat chivalry chive chloride chlorine choice chokehold choking " +
    "chomp chooser choosing choosy chop chosen chowder chowtime chrome chubby " +
    "chuck chug chummy chump chunk churn chute cider cilantro cinch " +
    "cinema cinnamon circle circling circular circulate circus citable citadel citation " +
    "citizen citric citrus city civic civil clad claim clambake clammy " +
    "clamor clamp clamshell clang clanking clapped clapper clapping clarify clarinet " +
    "clarity clash clasp class clatter clause clavicle claw clay clean " +
    "clear cleat cleaver cleft clench clergyman clerical clerk clever clicker " +
    "client climate climatic cling clinic clinking clip clique cloak clobber " +
    "clock clone cloning closable closure clothes clothing cloud clover clubbed " +
    "clubbing clubhouse clump clumsily clumsy clunky clustered clutch clutter coach " +
    "coagulant coastal coaster coasting coastland coastline coat coauthor cobalt cobbler " +
    "cobweb cocoa coconut cod coeditor coerce coexist coffee cofounder cognition " +
    "cognitive cogwheel coherence coherent cohesive coil coke cola cold coleslaw " +
    "coliseum collage collapse collar collected collector collide collie collision colonial " +
    "colonist colonize colony colossal colt coma come comfort comfy comic " +
    "coming comma commence commend comment commerce commode commodity commodore common " +
    "commotion commute commuting compacted compacter compactly compactor companion company compare " +
    "compel compile comply component composed composer composite compost composure compound " +
    "compress comprised computer computing comrade concave conceal conceded concept concerned " +
    "concert conch concierge concise conclude concrete concur condense condiment condition " +
    "condone conducive conductor conduit cone confess confetti confidant confident confider " +
    "confiding configure confined confining confirm conflict conform confound confront confused " +
    "confusing confusion congenial congested congrats congress conical conjoined conjure conjuror " +
    "connected connector consensus consent console consoling consonant constable constant constrain " +
    "constrict construct consult consumer consuming contact container contempt contend contented " +
    "contently contents contest context contort contour contrite control contusion convene " +
    "convent copartner cope copied copier copilot coping copious copper copy " +
    "coral cork cornball cornbread corncob cornea corned corner cornfield cornflake " +
    "cornhusk cornmeal cornstalk corny coronary coroner corporal corporate corral correct " +
    "corridor corrode corroding corrosive corsage corset cortex cosigner cosmetics cosmic " +
    "cosmos cosponsor cost cottage cotton couch cough could countable countdown " +
    "counting countless country county courier covenant cover coveted coveting coyness " +
    "cozily coziness cozy crabbing crabgrass crablike crabmeat cradle cradling crafter " +
    "craftily craftsman craftwork crafty cramp cranberry crane cranial cranium crank " +
    "crate crave craving crawfish crawlers crawling crayfish crayon crazed crazily " +
    "craziness crazy creamed creamer creamlike crease creasing creatable create creation " +
    "creative creature credible credibly credit creed creme creole crepe crept " +
    "crescent crested cresting crestless crevice crewless crewman crewmate crib cricket " +
    "cried crier crimp crimson cringe cringing crinkle crinkly crisped crisping " +
    "crisply crispness crispy criteria critter croak crock crook croon crop " +
    "cross crouch crouton crowbar crowd crown crucial crudely crudeness cruelly " +
    "cruelness cruelty crumb crummiest crummy crumpet crumpled cruncher crunching crunchy " +
    "crusader crushable crushed crusher crushing crust crux crying cryptic crystal " +
    "cubbyhole cube cubical cubicle cucumber cuddle cuddly cufflink culinary culminate " +
    "culpable culprit cultivate cultural culture cupbearer cupcake cupid cupped cupping " +
    "curable curator curdle cure curfew curing curled curler curliness curling " +
    "curly curry curse cursive cursor curtain curtly curtsy curvature curve " +
    "curvy cushy cusp cussed custard custodian custody customary customer customize " +
    "customs cut cycle cyclic cycling cyclist cylinder cymbal cytoplasm cytoplast " +
    "dab dad daffodil dagger daily daintily dainty dairy daisy dallying " +
    "dance dancing dandelion dander dandruff dandy danger dangle dangling daredevil " +
    "dares daringly darkened darkening darkish darkness darkroom darling darn dart " +
    "darwinism dash dastardly data datebook dating daughter daunting dawdler dawn " +
    "daybed daybreak daycare daydream daylight daylong dayroom daytime dazzler dazzling " +
    "deacon deafening deafness dealer dealing dealmaker dealt dean debatable debate " +
    "debating debit debrief debtless debtor debug debunk decade decaf decal " +
    "decathlon decay deceased deceit deceiver deceiving december decency decent deception " +
    "deceptive decibel decidable decimal decimeter decipher deck declared decline decode " +
    "decompose decorated decorator decoy decrease decree dedicate dedicator deduce deduct " +
    "deed deem deepen deeply deepness deface defacing defame default defeat " +
    "defection defective defendant defender defense defensive deferral deferred defiance defiant " +
    "defile defiling define definite deflate deflation deflator deflected deflector defog " +
    "deforest defraud defrost deftly defuse defy degraded degrading degrease degree " +
    "dehydrate deity dejected delay delegate delegator delete deletion delicacy delicate " +
    "delicious delighted delirious delirium deliverer delivery delouse delta deluge delusion " +
    "deluxe demanding demeaning demeanor demise democracy democrat demote demotion demystify " +
    "denatured deniable denial denim denote dense density dental dentist denture " +
    "deny deodorant deodorize departed departure depict deplete depletion deplored deploy " +
    "deport depose depraved depravity deprecate depress deprive depth deputize deputy " +
    "derail deranged derby derived desecrate deserve deserving designate designed designer " +
    "designing deskbound desktop deskwork desolate despair despise despite destiny destitute " +
    "destruct detached detail detection detective detector detention detergent detest detonate " +
    "detonator detoxify detract deuce devalue deviancy deviant deviate deviation deviator " +
    "device devious devotedly devotee devotion devourer devouring devoutly dexterity dexterous " +
    "diabetes diabetic diabolic diagnoses diagnosis diagram dial diameter diaper diaphragm " +
    "diary dice dicing dictate dictation dictator difficult diffused diffuser diffusion " +
    "diffusive dig dilation diligence diligent dill dilute dime diminish dimly " +
    "dimmed dimmer dimness dimple diner dingbat dinghy dinginess dingo dingy " +
    "dining dinner diocese dioxide diploma dipped dipper dipping directed direction " +
    "directive directly directory direness dirtiness disabled disagree disallow disarm disarray " +
    "disaster disband disbelief disburse discard discern discharge disclose discolor discount " +
    "discourse discover discuss disdain disengage disfigure disgrace dish disinfect disjoin " +
    "disk dislike disliking dislocate dislodge disloyal dismantle dismay dismiss dismount " +
    "disobey disorder disown disparate disparity dispatch dispense dispersal dispersed disperser " +
    "displace display displease disposal dispose disprove dispute disregard disrupt dissuade " +
    "distance distant distaste distill distinct distort distract distress district distrust " +
    "ditch ditto ditzy dividable divided dividend dividers dividing divinely diving " +
    "divinity divisible divisibly division divisive divorcee dizziness dizzy doable docile " +
    "dock doctrine document dodge dodgy doily doing dole dollar dollhouse " +
    "dollop dolly dolphin domain domelike domestic dominion dominoes donated donation " +
    "donator donor donut doodle doorbell doorframe doorknob doorman doormat doornail " +
    "doorpost doorstep doorstop doorway doozy dork dormitory dorsal dosage dose " +
    "dotted doubling douche dove down dowry doze drab dragging dragonfly " +
    "dragonish dragster drainable drainage drained drainer drainpipe dramatic dramatize drank " +
    "drapery drastic draw dreaded dreadful dreadlock dreamboat dreamily dreamland dreamless " +
    "dreamlike dreamt dreamy drearily dreary drench dress drew dribble dried " +
    "drier drift driller drilling drinkable drinking dripping drippy drivable driven " +
    "driver driveway driving drizzle drizzly drone drool droop dropbox dropdown " +
    "dropkick droplet dropout dropper drove drown drowsily drudge drum dry " +
    "dubbed dubiously duchess duckbill ducking duckling ducktail ducky duct dude " +
    "duffel dugout duh duke duller dullness duly dumping dumpling dumpster " +
    "duo dupe duplex duplicate duplicity durable durably duration duress during " +
    "dusk dust dutiful duty duvet dwarf dweeb dwelled dweller dwelling " +
    "dwindle dwindling dynamic dynamite dynasty dyslexia dyslexic each eagle earache " +
    "eardrum earflap earful earlobe early earmark earmuff earphone earpiece earplugs " +
    "earring earshot earthen earthlike earthling earthly earthworm earthy earwig easeful " +
    "easel easiest easily easiness easing eastbound eastcoast easter eastward eatable " +
    "eaten eatery eating eats ebay ebony ebook ecard eccentric echo " +
    "eclair eclipse ecologist ecology economic economist economy ecosphere ecosystem edge " +
    "edginess edging edgy edition editor educated education educator eel effective " +
    "effects efficient effort eggbeater egging eggnog eggplant eggshell egomaniac egotism " +
    "egotistic either eject elaborate elastic elated elbow eldercare elderly eldest " +
    "electable election elective elephant elevate elevating elevation elevator eleven elf " +
    "eligible eligibly eliminate elite elitism elixir elk ellipse elliptic elm " +
    "elongated elope eloquence eloquent elsewhere elude elusive elves email embargo " +
    "embark embassy embattled embellish ember embezzle emblaze emblem embody embolism " +
    "emboss embroider emcee emerald emergency emission emit emote emoticon emotion " +
    "empathic empathy emperor emphases emphasis emphasize emphatic empirical employed employee " +
    "employer emporium empower emptier emptiness empty emu enable enactment enamel " +
    "enchanted enchilada encircle enclose enclosure encode encore encounter encourage encroach " +
    "encrust encrypt endanger endeared endearing ended ending endless endnote endocrine " +
    "endorphin endorse endowment endpoint endurable endurance enduring energetic energize energy " +
    "enforced enforcer engaged engaging engine engorge engraved engraver engraving engross " +
    "engulf enhance enigmatic enjoyable enjoyably enjoyer enjoying enjoyment enlarged enlarging " +
    "enlighten enlisted enquirer enrage enrich enroll enslave ensnare ensure entail " +
    "entangled entering entertain enticing entire entitle entity entomb entourage entrap " +
    "entree entrench entrust entryway entwine enunciate envelope enviable enviably envious " +
    "envision envoy envy enzyme epic epidemic epidermal epidermis epidural epilepsy " +
    "epileptic epilogue epiphany episode equal equate equation equator equinox equipment " +
    "equity equivocal eradicate erasable erased eraser erasure ergonomic errand errant " +
    "erratic error erupt escalate escalator escapable escapade escapist escargot eskimo " +
    "esophagus espionage espresso esquire essay essence essential establish estate esteemed " +
    "estimate estimator estranged estrogen etching eternal eternity ethanol ether ethically " +
    "ethics euphemism evacuate evacuee evade evaluate evaluator evaporate evasion evasive " +
    "even everglade evergreen everybody everyday everyone evict evidence evident evil " +
    "evoke evolution evolve exact exalted example excavate excavator exceeding exception " +
    "excess exchange excitable exciting exclaim exclude excluding exclusion exclusive excretion " +
    "excretory excursion excusable excusably excuse exemplary exemplify exemption exerciser exert " +
    "exes exfoliate exhale exhaust exhume exile existing exit exodus exonerate " +
    "exorcism exorcist expand expanse expansion expansive expectant expedited expediter expel " +
    "expend expenses expensive expert expire expiring explain expletive explicit explode " +
    "exploit explore exploring exponent exporter exposable expose exposure express expulsion " +
    "exquisite extended extending extent extenuate exterior external extinct extortion extradite " +
    "extras extrovert extrude extruding exuberant fable fabric fabulous facebook facecloth " +
    "facedown faceless facelift faceplate faceted facial facility facing facsimile faction " +
    "factoid factor factsheet factual faculty fade fading failing falcon fall " +
    "false falsify fame familiar family famine famished fanatic fancied fanciness " +
    "fancy fanfare fang fanning fantasize fantastic fantasy fascism fastball faster " +
    "fasting fastness faucet favorable favorably favored favoring favorite fax feast " +
    "federal fedora feeble feed feel feisty feline felttip feminine feminism " +
    "feminist feminize femur fence fencing fender ferment fernlike ferocious ferocity " +
    "ferret ferris ferry fervor fester festival festive festivity fetal fetch " +
    "fever fiber fiction fiddle fiddling fidelity fidgeting fidgety fifteen fifth " +
    "fiftieth fifty figment figure figurine filing filled filler filling film " +
    "filter filth filtrate finale finalist finalize finally finance financial finch " +
    "fineness finer finicky finished finisher finishing finite finless finlike fiscally " +
    "fit five flaccid flagman flagpole flagship flagstick flagstone flail flakily " +
    "flaky flame flammable flanked flanking flannels flap flaring flashback flashbulb " +
    "flashcard flashily flashing flashy flask flatbed flatfoot flatly flatness flatten " +
    "flattered flatterer flattery flattop flatware flatworm flavored flavorful flavoring flaxseed " +
    "fled fleshed fleshy flick flier flight flinch fling flint flip " +
    "flirt float flock flogging flop floral florist floss flounder flyable " +
    "flyaway flyer flying flyover flypaper foam foe fog foil folic " +
    "folk follicle follow fondling fondly fondness fondue font food fool " +
    "footage football footbath footboard footer footgear foothill foothold footing footless " +
    "footman footnote footpad footpath footprint footrest footsie footsore footwear footwork " +
    "fossil foster founder founding fountain fox foyer fraction fracture fragile " +
    "fragility fragment fragrance fragrant frail frame framing frantic fraternal frayed " +
    "fraying frays freckled freckles freebase freebee freebie freedom freefall freehand " +
    "freeing freeload freely freemason freeness freestyle freeware freeway freewill freezable " +
    "freezing freight french frenzied frenzy frequency frequent fresh fretful fretted " +
    "friction friday fridge fried friend frighten frightful frigidity frigidly frill " +
    "fringe frisbee frisk fritter frivolous frolic from front frostbite frosted " +
    "frostily frosting frostlike frosty froth frown frozen fructose frugality frugally " +
    "fruit frustrate frying gab gaffe gag gainfully gaining gains gala " +
    "gallantly galleria gallery galley gallon gallows gallstone galore galvanize gambling " +
    "game gaming gamma gander gangly gangrene gangway gap garage garbage " +
    "garden gargle garland garlic garment garnet garnish garter gas gatherer " +
    "gathering gating gauging gauntlet gauze gave gawk gazing gear gecko " +
    "geek geiger gem gender generic generous genetics genre gentile gentleman " +
    "gently gents geography geologic geologist geology geometric geometry geranium gerbil " +
    "geriatric germicide germinate germless germproof gestate gestation gesture getaway getting " +
    "getup giant gibberish giblet giddily giddiness giddy gift gigabyte gigahertz " +
    "gigantic giggle giggling giggly gigolo gilled gills gimmick girdle giveaway " +
    "given giver giving gizmo gizzard glacial glacier glade gladiator gladly " +
    "glamorous glamour glance glancing glandular glare glaring glass glaucoma glazing " +
    "gleaming gleeful glider gliding glimmer glimpse glisten glitch glitter glitzy " +
    "gloater gloating gloomily gloomy glorified glorifier glorify glorious glory gloss " +
    "glove glowing glowworm glucose glue gluten glutinous glutton gnarly gnat " +
    "goal goatskin goes goggles going goldfish goldmine goldsmith golf goliath " +
    "gonad gondola gone gong good gooey goofball goofiness goofy google " +
    "goon gopher gore gorged gorgeous gory gosling gossip gothic gotten " +
    "gout gown grab graceful graceless gracious gradation graded grader gradient " +
    "grading gradually graduate graffiti grafted grafting grain granddad grandkid grandly " +
    "grandma grandpa grandson granite granny granola grant granular grape graph " +
    "grapple grappling grasp grass gratified gratify grating gratitude gratuity gravel " +
    "graveness graves graveyard gravitate gravity gravy gray grazing greasily greedily " +
    "greedless greedy green greeter greeting grew greyhound grid grief grievance " +
    "grieving grievous grill grimace grimacing grime griminess grimy grinch grinning " +
    "grip gristle grit groggily groggy groin groom groove grooving groovy " +
    "grope ground grouped grout grove grower growing growl grub grudge " +
    "grudging grueling gruffly grumble grumbling grumbly grumpily grunge grunt guacamole " +
    "guidable guidance guide guiding guileless guise gulf gullible gully gulp " +
    "gumball gumdrop gumminess gumming gummy gurgle gurgling guru gush gusto " +
    "gusty gutless guts gutter guy guzzler gyration habitable habitant habitat " +
    "habitual hacked hacker hacking hacksaw had haggler haiku half halogen " +
    "halt halved halves hamburger hamlet hammock hamper hamster hamstring handbag " +
    "handball handbook handbrake handcart handclap handclasp handcraft handcuff handed handful " +
    "handgrip handgun handheld handiness handiwork handlebar handled handler handling handmade " +
    "handoff handpick handprint handrail handsaw handset handsfree handshake handstand handwash " +
    "handwork handwoven handwrite handyman hangnail hangout hangover hangup hankering hankie " +
    "hanky haphazard happening happier happiest happily happiness happy harbor hardcopy " +
    "hardcore hardcover harddisk hardened hardener hardening hardhat hardhead hardiness hardly " +
    "hardness hardship hardware hardwired hardwood hardy harmful harmless harmonica harmonics " +
    "harmonize harmony harness harpist harsh harvest hash hassle haste hastily " +
    "hastiness hasty hatbox hatchback hatchery hatchet hatching hatchling hate hatless " +
    "hatred haunt haven hazard hazelnut hazily haziness hazing hazy headache " +
    "headband headboard headcount headdress headed header headfirst headgear heading headlamp " +
    "headless headlock headphone headpiece headrest headroom headscarf headset headsman headstand " +
    "headstone headway headwear heap heat heave heavily heaviness heaving hedge " +
    "hedging heftiness hefty helium helmet helper helpful helping helpless helpline " +
    "hemlock hemstitch hence henchman henna herald herbal herbicide herbs heritage " +
    "hermit heroics heroism herring herself hertz hesitancy hesitant hesitate hexagon " +
    "hexagram hubcap huddle huddling huff hug hula hulk hull human " +
    "humble humbling humbly humid humiliate humility humming hummus humongous humorist " +
    "humorless humorous humpback humped humvee hunchback hundredth hunger hungrily hungry " +
    "hunk hunter hunting huntress huntsman hurdle hurled hurler hurling hurray " +
    "hurricane hurried hurry hurt husband hush husked huskiness hut hybrid " +
    "hydrant hydrated hydration hydrogen hydroxide hyperlink hypertext hyphen hypnoses hypnosis " +
    "hypnotic hypnotism hypnotist hypnotize hypocrisy hypocrite ibuprofen ice iciness icing " +
    "icky icon icy idealism idealist idealize ideally idealness identical identify " +
    "identity ideology idiocy idiom idly igloo ignition ignore iguana illicitly " +
    "illusion illusive image imaginary imagines imaging imbecile imitate imitation immature " +
    "immerse immersion imminent immobile immodest immorally immortal immovable immovably immunity " +
    "immunize impaired impale impart impatient impeach impeding impending imperfect imperial " +
    "impish implant implement implicate implicit implode implosion implosive imply impolite " +
    "important importer impose imposing impotence impotency impotent impound imprecise imprint " +
    "imprison impromptu improper improve improving improvise imprudent impulse impulsive impure " +
    "impurity iodine iodize ion ipad iphone ipod irate irk iron " +
    "irregular irrigate irritable irritably irritant irritate islamic islamist isolated isolating " +
    "isolation isotope issue issuing italicize italics item itinerary itunes ivory " +
    "ivy jab jackal jacket jackknife jackpot jailbird jailbreak jailer jailhouse " +
    "jalapeno jam janitor january jargon jarring jasmine jaundice jaunt java " +
    "jawed jawless jawline jaws jaybird jaywalker jazz jeep jeeringly jellied " +
    "jelly jersey jester jet jiffy jigsaw jimmy jingle jingling jinx " +
    "jitters jittery job jockey jockstrap jogger jogging john joining jokester " +
    "jokingly jolliness jolly jolt jot jovial joyfully joylessly joyous joyride " +
    "joystick jubilance jubilant judge judgingly judicial judiciary judo juggle juggling " +
    "jugular juice juiciness juicy jujitsu jukebox july jumble jumbo jump " +
    "junction juncture june junior juniper junkie junkman junkyard jurist juror " +
    "jury justice justifier justify justly justness juvenile kabob kangaroo karaoke " +
    "karate karma kebab keenly keenness keep keg kelp kennel kept " +
    "kerchief kerosene kettle kick kiln kilobyte kilogram kilometer kilowatt kilt " +
    "kimono kindle kindling kindly kindness kindred kinetic kinfolk king kinship " +
    "kinsman kinswoman kissable kisser kissing kitchen kite kitten kitty kiwi " +
    "kleenex knapsack knee knelt knickers knoll koala kooky kosher krypton " +
    "kudos kung labored laborer laboring laborious labrador ladder ladies ladle " +
    "ladybug ladylike lagged lagging lagoon lair lake lance landed landfall " +
    "landfill landing landlady landless landline landlord landmark landmass landmine landowner " +
    "landscape landside landslide language lankiness lanky lantern lapdog lapel lapped " +
    "lapping laptop lard large lark lash lasso last latch late " +
    "lather latitude latrine latter latticed launch launder laundry laurel lavender " +
    "lavish laxative lazily laziness lazy lecturer left legacy legal legend " +
    "legged leggings legible legibly legislate lego legroom legume legwarmer legwork " +
    "lemon lend length lens lent leotard lesser letdown lethargic lethargy " +
    "letter lettuce level leverage levers levitate levitator liability liable liberty " +
    "librarian library licking licorice lid life lifter lifting liftoff ligament " +
    "likely likeness likewise liking lilac lilly lily limb limeade limelight " +
    "limes limit limping limpness line lingo linguini linguist lining linked " +
    "linoleum linseed lint lion lip liquefy liqueur liquid lisp list " +
    "litigate litigator litmus litter little livable lived lively liver livestock " +
    "lividly living lizard lubricant lubricate lucid luckily luckiness luckless lucrative " +
    "ludicrous lugged lukewarm lullaby lumber luminance luminous lumpiness lumping lumpish " +
    "lunacy lunar lunchbox luncheon lunchroom lunchtime lung lurch lure luridness " +
    "lurk lushly lushness luster lustfully lustily lustiness lustrous lusty luxurious " +
    "luxury lying lyrically lyricism lyricist lyrics macarena macaroni macaw mace " +
    "machine machinist magazine magenta maggot magical magician magma magnesium magnetic " +
    "magnetism magnetize magnifier magnify magnitude magnolia mahogany maimed majestic majesty " +
    "majorette majority makeover maker makeshift making malformed malt mama mammal " +
    "mammary mammogram manager managing manatee mandarin mandate mandatory mandolin manger " +
    "mangle mango mangy manhandle manhole manhood manhunt manicotti manicure manifesto " +
    "manila mankind manlike manliness manly manmade manned mannish manor manpower " +
    "mantis mantra manual many map marathon marauding marbled marbles marbling " +
    "march mardi margarine margarita margin marigold marina marine marital maritime " +
    "marlin marmalade maroon married marrow marry marshland marshy marsupial marvelous " +
    "marxism mascot masculine mashed mashing massager masses massive mastiff matador " +
    "matchbook matchbox matcher matching matchless material maternal maternity math mating " +
    "matriarch matrimony matrix matron matted matter maturely maturing maturity mauve " +
    "maverick maximize maximum maybe mayday mayflower moaner moaning mobile mobility " +
    "mobilize mobster mocha mocker mockup modified modify modular modulator module " +
    "moisten moistness moisture molar molasses mold molecular molecule molehill mollusk " +
    "mom monastery monday monetary monetize moneybags moneyless moneywise mongoose mongrel " +
    "monitor monkhood monogamy monogram monologue monopoly monorail monotone monotype monoxide " +
    "monsieur monsoon monstrous monthly monument moocher moodiness moody mooing moonbeam " +
    "mooned moonlight moonlike moonlit moonrise moonscape moonshine moonstone moonwalk mop " +
    "morale morality morally morbidity morbidly morphine morphing morse mortality mortally " +
    "mortician mortified mortify mortuary mosaic mossy most mothball mothproof motion " +
    "motivate motivator motive motocross motor motto mountable mountain mounted mounting " +
    "mourner mournful mouse mousiness moustache mousy mouth movable move movie " +
    "moving mower mowing much muck mud mug mulberry mulch mule " +
    "mulled mullets multiple multiply multitask multitude mumble mumbling mumbo mummified " +
    "mummify mummy mumps munchkin mundane municipal muppet mural murkiness murky " +
    "murmuring muscular museum mushily mushiness mushroom mushy music musket muskiness " +
    "musky mustang mustard muster mustiness musty mutable mutate mutation mute " +
    "mutilated mutilator mutiny mutt mutual muzzle myself myspace mystified mystify " +
    "myth nacho nag nail name naming nanny nanometer nape napkin " +
    "napped napping nappy narrow nastily nastiness national native nativity natural " +
    "nature naturist nautical navigate navigator navy nearby nearest nearly nearness " +
    "neatly neatness nebula nebulizer nectar negate negation negative neglector negligee " +
    "negligent negotiate nemeses nemesis neon nephew nerd nervous nervy nest " +
    "net neurology neuron neurosis neurotic neuter neutron never next nibble " +
    "nickname nicotine niece nifty nimble nimbly nineteen ninetieth ninja nintendo " +
    "ninth nuclear nuclei nucleus nugget nullify number numbing numbly numbness " +
    "numeral numerate numerator numeric numerous nuptials nursery nursing nurture nutcase " +
    "nutlike nutmeg nutrient nutshell nuttiness nutty nuzzle nylon oaf oak " +
    "oasis oat obedience obedient obituary object obligate obliged oblivion oblivious " +
    "oblong obnoxious oboe obscure obscurity observant observer observing obsessed obsession " +
    "obsessive obsolete obstacle obstinate obstruct obtain obtrusive obtuse obvious occultist " +
    "occupancy occupant occupier occupy ocean ocelot octagon octane october octopus " +
    "ogle oil oink ointment okay old olive olympics omega omen " +
    "ominous omission omit omnivore onboard oncoming ongoing onion online onlooker " +
    "only onscreen onset onshore onslaught onstage onto onward onyx oops " +
    "ooze oozy opacity opal open operable operate operating operation operative " +
    "operator opium opossum opponent oppose opposing opposite oppressed oppressor opt " +
    "opulently osmosis other otter ouch ought ounce outage outback outbid " +
    "outboard outbound outbreak outburst outcast outclass outcome outdated outdoors outer " +
    "outfield outfit outflank outgoing outgrow outhouse outing outlast outlet outline " +
    "outlook outlying outmatch outmost outnumber outplayed outpost outpour output outrage " +
    "outrank outreach outright outscore outsell outshine outshoot outsider outskirts outsmart " +
    "outsource outspoken outtakes outthink outward outweigh outwit oval ovary oven " +
    "overact overall overarch overbid overbill overbite overblown overboard overbook overbuilt " +
    "overcast overcoat overcome overcook overcrowd overdraft overdrawn overdress overdrive overdue " +
    "overeager overeater overexert overfed overfeed overfill overflow overfull overgrown overhand " +
    "overhang overhaul overhead overhear overheat overhung overjoyed overkill overlabor overlaid " +
    "overlap overlay overload overlook overlord overlying overnight overpass overpay overplant " +
    "overplay overpower overprice overrate overreach overreact override overripe overrule overrun " +
    "overshoot overshot oversight oversized oversleep oversold overspend overstate overstay overstep " +
    "overstock overstuff oversweet overtake overthrow overtime overtly overtone overture overturn " +
    "overuse overvalue overview overwrite owl oxford oxidant oxidation oxidize oxidizing " +
    "oxygen oxymoron oyster ozone paced pacemaker pacific pacifier pacifism pacifist " +
    "pacify padded padding paddle paddling padlock pagan pager paging pajamas " +
    "palace palatable palm palpable palpitate paltry pampered pamperer pampers pamphlet " +
    "panama pancake pancreas panda pandemic pang panhandle panic panning panorama " +
    "panoramic panther pantomime pantry pants pantyhose paparazzi papaya paper paprika " +
    "papyrus parabola parachute parade paradox paragraph parakeet paralegal paralyses paralysis " +
    "paralyze paramedic parameter paramount parasail parasite parasitic parcel parched parchment " +
    "pardon parish parka parking parkway parlor parmesan parole parrot parsley " +
    "parsnip partake parted parting partition partly partner partridge party passable " +
    "passably passage passcode passenger passerby passing passion passive passivism passover " +
    "passport password pasta pasted pastel pastime pastor pastrami pasture pasty " +
    "patchwork patchy paternal paternity path patience patient patio patriarch patriot " +
    "patrol patronage patronize pauper pavement paver pavestone pavilion paving pawing " +
    "payable payback paycheck payday payee payer paying payment payphone payroll " +
    "pebble pebbly pecan pectin peculiar peddling pediatric pedicure pedigree pedometer " +
    "pegboard pelican pellet pelt pelvis penalize penalty pencil pendant pending " +
    "penholder penknife pennant penniless penny penpal pension pentagon pentagram pep " +
    "perceive percent perch percolate perennial perfected perfectly perfume periscope perish " +
    "perjurer perjury perkiness perky perm peroxide perpetual perplexed persecute persevere " +
    "persuaded persuader pesky peso pessimism pessimist pester pesticide petal petite " +
    "petition petri petroleum petted petticoat pettiness petty petunia phantom phobia " +
    "phoenix phonebook phoney phonics phoniness phony phosphate photo phrase phrasing " +
    "placard placate placidly plank planner plant plasma plaster plastic plated " +
    "platform plating platinum platonic platter platypus plausible plausibly playable playback " +
    "player playful playgroup playhouse playing playlist playmaker playmate playoff playpen " +
    "playroom playset plaything playtime plaza pleading pleat pledge plentiful plenty " +
    "plethora plexiglas pliable plod plop plot plow ploy pluck plug " +
    "plunder plunging plural plus plutonium plywood poach pod poem poet " +
    "pogo pointed pointer pointing pointless pointy poise poison poker poking " +
    "polar police policy polio polish politely polka polo polyester polygon " +
    "polygraph polymer poncho pond pony popcorn pope poplar popper poppy " +
    "popsicle populace popular populate porcupine pork porous porridge portable portal " +
    "portfolio porthole portion portly portside poser posh posing possible possibly " +
    "possum postage postal postbox postcard posted poster posting postnasal posture " +
    "postwar pouch pounce pouncing pound pouring pout powdered powdering powdery " +
    "power powwow pox praising prance prancing pranker prankish prankster prayer " +
    "praying preacher preaching preachy preamble precinct precise precision precook precut " +
    "predator predefine predict preface prefix preflight preformed pregame pregnancy pregnant " +
    "preheated prelaunch prelaw prelude premiere premises premium prenatal preoccupy preorder " +
    "prepaid prepay preplan preppy preschool prescribe preseason preset preshow president " +
    "presoak press presume presuming preteen pretended pretender pretense pretext pretty " +
    "pretzel prevail prevalent prevent preview previous prewar prewashed prideful pried " +
    "primal primarily primary primate primer primp princess print prior prism " +
    "prison prissy pristine privacy private privatize prize proactive probable probably " +
    "probation probe probing probiotic problem procedure process proclaim procreate procurer " +
    "prodigal prodigy produce product profane profanity professed professor profile profound " +
    "profusely progeny prognosis program progress projector prologue prolonged promenade prominent " +
    "promoter promotion prompter promptly prone prong pronounce pronto proofing proofread " +
    "proofs propeller properly property proponent proposal propose props prorate protector " +
    "protegee proton prototype protozoan protract protrude proud provable proved proven " +
    "provided provider providing province proving provoke provoking provolone prowess prowler " +
    "prowling proximity proxy prozac prude prudishly prune pruning pry psychic " +
    "public publisher pucker pueblo pug pull pulmonary pulp pulsate pulse " +
    "pulverize puma pumice pummel punch punctual punctuate punctured pungent punisher " +
    "punk pupil puppet puppy purchase pureblood purebred purely pureness purgatory " +
    "purge purging purifier purify purist puritan purity purple purplish purposely " +
    "purr purse pursuable pursuant pursuit purveyor pushcart pushchair pusher pushiness " +
    "pushing pushover pushpin pushup pushy putdown putt puzzle puzzling pyramid " +
    "pyromania python quack quadrant quail quaintly quake quaking qualified qualifier " +
    "qualify quality qualm quantum quarrel quarry quartered quarterly quarters quartet " +
    "quench query quicken quickly quickness quicksand quickstep quiet quill quilt " +
    "quintet quintuple quirk quit quiver quizzical quotable quotation quote rabid " +
    "race racing racism rack racoon radar radial radiance radiantly radiated " +
    "radiation radiator radio radish raffle raft rage ragged raging ragweed " +
    "raider railcar railing railroad railway raisin rake raking rally ramble " +
    "rambling ramp ramrod ranch rancidity random ranged ranger ranging ranked " +
    "ranking ransack ranting rants rare rarity rascal rash rasping ravage " +
    "raven ravine raving ravioli ravishing reabsorb reach reacquire reaction reactive " +
    "reactor reaffirm ream reanalyze reappear reapply reappoint reapprove rearrange rearview " +
    "reason reassign reassure reattach reawake rebalance rebate rebel rebirth reboot " +
    "reborn rebound rebuff rebuild rebuilt reburial rebuttal recall recant recapture " +
    "recast recede recent recess recharger recipient recital recite reckless reclaim " +
    "recliner reclining recluse reclusive recognize recoil recollect recolor reconcile reconfirm " +
    "reconvene recopy record recount recoup recovery recreate rectal rectangle rectified " +
    "rectify recycled recycler recycling reemerge reenact reenter reentry reexamine referable " +
    "referee reference refill refinance refined refinery refining refinish reflected reflector " +
    "reflex reflux refocus refold reforest reformat reformed reformer reformist refract " +
    "refrain refreeze refresh refried refueling refund refurbish refurnish refusal refuse " +
    "refusing refutable refute regain regalia regally reggae regime region register " +
    "registrar registry regress regretful regroup regular regulate regulator rehab reheat " +
    "rehire rehydrate reimburse reissue reiterate rejoice rejoicing rejoin rekindle relapse " +
    "relapsing relatable related relation relative relax relay relearn release relenting " +
    "reliable reliably reliance reliant relic relieve relieving relight relish relive " +
    "reload relocate relock reluctant rely remake remark remarry rematch remedial " +
    "remedy remember reminder remindful remission remix remnant remodeler remold remorse " +
    "remote removable removal removed remover removing rename renderer rendering rendition " +
    "renegade renewable renewably renewal renewed renounce renovate renovator rentable rental " +
    "rented renter reoccupy reoccur reopen reorder repackage repacking repaint repair " +
    "repave repaying repayment repeal repeated repeater repent rephrase replace replay " +
    "replica reply reporter repose repossess repost repressed reprimand reprint reprise " +
    "reproach reprocess reproduce reprogram reps reptile reptilian repugnant repulsion repulsive " +
    "repurpose reputable reputably request require requisite reroute rerun resale resample " +
    "rescuer reseal research reselect reseller resemble resend resent reset reshape " +
    "reshoot reshuffle residence residency resident residual residue resigned resilient resistant " +
    "resisting resize resolute resolved resonant resonate resort resource respect resubmit " +
    "result resume resupply resurface resurrect retail retainer retaining retake retaliate " +
    "retention rethink retinal retired retiree retiring retold retool retorted retouch " +
    "retrace retract retrain retread retreat retrial retrieval retriever retry return " +
    "retying retype reunion reunite reusable reuse reveal reveler revenge revenue " +
    "reverb revered reverence reverend reversal reverse reversing reversion revert revisable " +
    "revise revision revisit revivable revival reviver reviving revocable revoke revolt " +
    "revolver revolving reward rewash rewind rewire reword rework rewrap rewrite " +
    "rhyme ribbon ribcage rice riches richly richness rickety ricotta riddance " +
    "ridden ride riding rifling rift rigging rigid rigor rimless rimmed " +
    "rind rink rinse rinsing riot ripcord ripeness ripening ripping ripple " +
    "rippling riptide rise rising risk risotto ritalin ritzy rival riverbank " +
    "riverbed riverboat riverside riveter riveting roamer roaming roast robbing robe " +
    "robin robotics robust rockband rocker rocket rockfish rockiness rocking rocklike " +
    "rockslide rockstar rocky rogue roman romp rope roping roster rosy " +
    "rotten rotting rotunda roulette rounding roundish roundness roundup roundworm routine " +
    "routing rover roving royal rubbed rubber rubbing rubble rubdown ruby " +
    "ruckus rudder rug ruined rule rumble rumbling rummage rumor runaround " +
    "rundown runner running runny runt runway rupture rural ruse rush " +
    "rust rut sabbath sabotage sacrament sacred sacrifice sadden saddlebag saddled " +
    "saddling sadly sadness safari safeguard safehouse safely safeness saffron saga " +
    "sage sagging saggy said saint sake salad salami salaried salary " +
    "saline salon saloon salsa salt salutary salute salvage salvaging salvation " +
    "same sample sampling sanction sanctity sanctuary sandal sandbag sandbank sandbar " +
    "sandblast sandbox sanded sandfish sanding sandlot sandpaper sandpit sandstone sandstorm " +
    "sandworm sandy sanitary sanitizer sank santa sapling sappiness sappy sarcasm " +
    "sarcastic sardine sash sasquatch sassy satchel satiable satin satirical satisfied " +
    "satisfy saturate saturday sauciness saucy sauna savage savanna saved savings " +
    "savior savor saxophone say scabbed scabby scalded scalding scale scaling " +
    "scallion scallop scalping scam scandal scanner scanning scant scapegoat scarce " +
    "scarcity scarecrow scared scarf scarily scariness scarring scary scavenger scenic " +
    "schedule schematic scheme scheming schilling schnapps scholar science scientist scion " +
    "scoff scolding scone scoop scooter scope scorch scorebook scorecard scored " +
    "scoreless scorer scoring scorn scorpion scotch scoundrel scoured scouring scouting " +
    "scouts scowling scrabble scraggly scrambled scrambler scrap scratch scrawny screen " +
    "scribble scribe scribing scrimmage script scroll scrooge scrounger scrubbed scrubber " +
    "scruffy scrunch scrutiny scuba scuff sculptor sculpture scurvy scuttle secluded " +
    "secluding seclusion second secrecy secret sectional sector secular securely security " +
    "sedan sedate sedation sedative sediment seduce seducing segment seismic seizing " +
    "seldom selected selection selective selector self seltzer semantic semester semicolon " +
    "semifinal seminar semisoft semisweet senate senator send senior senorita sensation " +
    "sensitive sensitize sensually sensuous sepia september septic septum sequel sequence " +
    "sequester series sermon serotonin serpent serrated serve service serving sesame " +
    "sessions setback setting settle settling setup sevenfold seventeen seventh seventy " +
    "severity shabby shack shaded shadily shadiness shading shadow shady shaft " +
    "shakable shakily shakiness shaking shaky shale shallot shallow shame shampoo " +
    "shamrock shank shanty shape shaping share sharpener sharper sharpie sharply " +
    "sharpness shawl sheath shed sheep sheet shelf shell shelter shelve " +
    "shelving sherry shield shifter shifting shiftless shifty shimmer shimmy shindig " +
    "shine shingle shininess shining shiny ship shirt shivering shock shone " +
    "shoplift shopper shopping shoptalk shore shortage shortcake shortcut shorten shorter " +
    "shorthand shortlist shortly shortness shorts shortwave shorty shout shove showbiz " +
    "showcase showdown shower showgirl showing showman shown showoff showpiece showplace " +
    "showroom showy shrank shrapnel shredder shredding shrewdly shriek shrill shrimp " +
    "shrine shrink shrivel shrouded shrubbery shrubs shrug shrunk shucking shudder " +
    "shuffle shuffling shun shush shut shy siamese siberian sibling siding " +
    "sierra siesta sift sighing silenced silencer silent silica silicon silk " +
    "silliness silly silo silt silver similarly simile simmering simple simplify " +
    "simply sincere sincerity singer singing single singular sinister sinless sinner " +
    "sinuous sip siren sister sitcom sitter sitting situated situation sixfold " +
    "sixteen sixth sixties sixtieth sixtyfold sizable sizably size sizing sizzle " +
    "sizzling skater skating skedaddle skeletal skeleton skeptic sketch skewed skewer " +
    "skid skied skier skies skiing skilled skillet skillful skimmed skimmer " +
    "skimming skimpily skincare skinhead skinless skinning skinny skintight skipper skipping " +
    "skirmish skirt skittle skydiver skylight skyline skype skyrocket skyward slab " +
    "slacked slacker slacking slackness slacks slain slam slander slang slapping " +
    "slapstick slashed slashing slate slather slaw sled sleek sleep sleet " +
    "sleeve slept sliceable sliced slicer slicing slick slider slideshow sliding " +
    "slighted slighting slightly slimness slimy slinging slingshot slinky slip slit " +
    "sliver slobbery slogan sloped sloping sloppily sloppy slot slouching slouchy " +
    "sludge slug slum slurp slush sly small smartly smartness smasher " +
    "smashing smashup smell smelting smile smilingly smirk smite smith smitten " +
    "smock smog smoked smokeless smokiness smoking smoky smolder smooth smother " +
    "smudge smudgy smuggler smuggling smugly smugness snack snagged snaking snap " +
    "snare snarl snazzy sneak sneer sneeze sneezing snide sniff snippet " +
    "snipping snitch snooper snooze snore snoring snorkel snort snout snowbird " +
    "snowboard snowbound snowcap snowdrift snowdrop snowfall snowfield snowflake snowiness snowless " +
    "snowman snowplow snowshoe snowstorm snowsuit snowy snub snuff snuggle snugly " +
    "snugness speak spearfish spearhead spearman spearmint species specimen specked speckled " +
    "specks spectacle spectator spectrum speculate speech speed spellbind speller spelling " +
    "spendable spender spending spent spew sphere spherical sphinx spider spied " +
    "spiffy spill spilt spinach spinal spindle spinner spinning spinout spinster " +
    "spiny spiral spirited spiritism spirits spiritual splashed splashing splashy splatter " +
    "spleen splendid splendor splice splicing splinter splotchy splurge spoilage spoiled " +
    "spoiler spoiling spoils spoken spokesman sponge spongy sponsor spoof spookily " +
    "spooky spool spoon spore sporting sports sporty spotless spotlight spotted " +
    "spotter spotting spotty spousal spouse spout sprain sprang sprawl spray " +
    "spree sprig spring sprinkled sprinkler sprint sprite sprout spruce sprung " +
    "spry spud spur sputter spyglass squabble squad squall squander squash " +
    "squatted squatter squatting squeak squealer squealing squeamish squeegee squeeze squeezing " +
    "squid squiggle squiggly squint squire squirt squishier squishy stability stabilize " +
    "stable stack stadium staff stage staging stagnant stagnate stainable stained " +
    "staining stainless stalemate staleness stalling stallion stamina stammer stamp stand " +
    "stank staple stapling starboard starch stardom stardust starfish stargazer staring " +
    "stark starless starlet starlight starlit starring starry starship starter starting " +
    "startle startling startup starved starving stash state static statistic statue " +
    "stature status statute statutory staunch stays steadfast steadier steadily steadying " +
    "steam steed steep steerable steering steersman stegosaur stellar stem stench " +
    "stencil step stereo sterile sterility sterilize sterling sternness sternum stew " +
    "stick stiffen stiffly stiffness stifle stifling stillness stilt stimulant stimulate " +
    "stimuli stimulus stinger stingily stinging stingray stingy stinking stinky stipend " +
    "stipulate stir stitch stock stoic stoke stole stomp stonewall stoneware " +
    "stonework stoning stony stood stooge stool stoop stoplight stoppable stoppage " +
    "stopped stopper stopping stopwatch storable storage storeroom storewide storm stout " +
    "stove stowaway stowing straddle straggler strained strainer straining strangely stranger " +
    "strangle strategic strategy stratus straw stray streak stream street strength " +
    "strenuous strep stress stretch strewn stricken strict stride strife strike " +
    "striking strive striving strobe strode stroller strongbox strongly strongman struck " +
    "structure strudel struggle strum strung strut stubbed stubble stubbly stubborn " +
    "stucco stuck student studied studio study stuffed stuffing stuffy stumble " +
    "stumbling stump stung stunned stunner stunning stunt stupor sturdily sturdy " +
    "styling stylishly stylist stylized stylus suave subarctic subatomic subdivide subdued " +
    "subduing subfloor subgroup subheader subject sublease sublet sublevel sublime submarine " +
    "submerge submersed submitter subpanel subpar subplot subprime subscribe subscript subsector " +
    "subside subsiding subsidize subsidy subsoil subsonic substance subsystem subtext subtitle " +
    "subtly subtotal subtract subtype suburb subway subwoofer subzero succulent such " +
    "suction sudden sudoku suds sufferer suffering suffice suffix suffocate suffrage " +
    "sugar suggest suing suitable suitably suitcase suitor sulfate sulfide sulfite " +
    "sulfur sulk sullen sulphate sulphuric sultry superbowl superglue superhero superior " +
    "superjet superman supermom supernova supervise supper supplier supply support supremacy " +
    "supreme surcharge surely sureness surface surfacing surfboard surfer surgery surgical " +
    "surging surname surpass surplus surprise surreal surrender surrogate surround survey " +
    "survival survive surviving survivor sushi suspect suspend suspense sustained sustainer " +
    "swab swaddling swagger swampland swan swapping swarm sway swear sweat " +
    "sweep swell swept swerve swifter swiftly swiftness swimmable swimmer swimming " +
    "swimsuit swimwear swinger swinging swipe swirl switch swivel swizzle swooned " +
    "swoop swoosh swore sworn swung sycamore sympathy symphonic symphony symptom " +
    "synapse syndrome synergy synopses synopsis synthesis synthetic syrup system tabasco " +
    "tabby tableful tables tablet tableware tabloid tackiness tacking tackle tackling " +
    "tacky taco tactful tactical tactics tactile tactless tadpole taekwondo tag " +
    "tainted take taking talcum talisman tall talon tamale tameness tamer " +
    "tamper tank tanned tannery tanning tantrum tapeless tapered tapering tapestry " +
    "tapioca tapping taps tarantula target tarmac tarnish tarot tartar tartly " +
    "tartness task tassel taste tastiness tasting tasty tattered tattle tattling " +
    "tattoo taunt tavern thank that thaw theater theatrics thee theft " +
    "theme theology theorize thermal thermos thesaurus these thesis thespian thicken " +
    "thicket thickness thieving thievish thigh thimble thing think thinly thinner " +
    "thinness thinning thirstily thirsting thirsty thirteen thirty thong thorn those " +
    "thousand thrash thread threaten threefold thrift thrill thrive thriving throat " +
    "throbbing throng throttle throwaway throwback thrower throwing thud thumb thumping " +
    "thursday thus thwarting thyself tiara tibia tidal tidbit tidiness tidings " +
    "tidy tiger tighten tightly tightness tightrope tightwad tigress tile tiling " +
    "till tilt timid timing timothy tinderbox tinfoil tingle tingling tingly " +
    "tinker tinkling tinsel tinsmith tint tinwork tiny tipoff tipped tipper " +
    "tipping tiptoeing tiptop tiring tissue trace tracing track traction tractor " +
    "trade trading tradition traffic tragedy trailing trailside train traitor trance " +
    "tranquil transfer transform translate transpire transport transpose trapdoor trapeze trapezoid " +
    "trapped trapper trapping traps trash travel traverse travesty tray treachery " +
    "treading treadmill treason treat treble tree trekker tremble trembling tremor " +
    "trench trend trespass triage trial triangle tribesman tribunal tribune tributary " +
    "tribute triceps trickery trickily tricking trickle trickster tricky tricolor tricycle " +
    "trident tried trifle trifocals trillion trilogy trimester trimmer trimming trimness " +
    "trinity trio tripod tripping triumph trivial trodden trolling trombone trophy " +
    "tropical tropics trouble troubling trough trousers trout trowel truce truck " +
    "truffle trump trunks trustable trustee trustful trusting trustless truth try " +
    "tshirt tubby tubeless tubular tucking tuesday tug tuition tulip tumble " +
    "tumbling tummy turban turbine turbofan turbojet turbulent turf turkey turmoil " +
    "turret turtle tusk tutor tutu tux tweak tweed tweet tweezers " +
    "twelve twentieth twenty twerp twice twiddle twiddling twig twilight twine " +
    "twins twirl twistable twisted twister twisting twisty twitch twitter tycoon " +
    "tying tyke udder ultimate ultimatum ultra umbilical umbrella umpire unabashed " +
    "unable unadorned unadvised unafraid unaired unaligned unaltered unarmored unashamed unaudited " +
    "unawake unaware unbaked unbalance unbeaten unbend unbent unbiased unbitten unblended " +
    "unblessed unblock unbolted unbounded unboxed unbraided unbridle unbroken unbuckled unbundle " +
    "unburned unbutton uncanny uncapped uncaring uncertain unchain unchanged uncharted uncheck " +
    "uncivil unclad unclaimed unclamped unclasp uncle unclip uncloak unclog unclothed " +
    "uncoated uncoiled uncolored uncombed uncommon uncooked uncork uncorrupt uncounted uncouple " +
    "uncouth uncover uncross uncrown uncrushed uncured uncurious uncurled uncut undamaged " +
    "undated undaunted undead undecided undefined underage underarm undercoat undercook undercut " +
    "underdog underdone underfed underfeed underfoot undergo undergrad underhand underline underling " +
    "undermine undermost underpaid underpass underpay underrate undertake undertone undertook undertow " +
    "underuse underwear underwent underwire undesired undiluted undivided undocked undoing undone " +
    "undrafted undress undrilled undusted undying unearned unearth unease uneasily uneasy " +
    "uneatable uneaten unedited unelected unending unengaged unenvied unequal unethical uneven " +
    "unexpired unexposed unfailing unfair unfasten unfazed unfeeling unfiled unfilled unfitted " +
    "unfitting unfixable unfixed unflawed unfocused unfold unfounded unframed unfreeze unfrosted " +
    "unfrozen unfunded unglazed ungloved unglue ungodly ungraded ungreased unguarded unguided " +
    "unhappily unhappy unharmed unhealthy unheard unhearing unheated unhelpful unhidden unhinge " +
    "unhitched unholy unhook unicorn unicycle unified unifier uniformed uniformly unify " +
    "unimpeded uninjured uninstall uninsured uninvited union uniquely unisexual unison unissued " +
    "unit universal universe unjustly unkempt unkind unknotted unknowing unknown unlaced " +
    "unlatch unlawful unleaded unlearned unleash unless unleveled unlighted unlikable unlimited " +
    "unlined unlinked unlisted unlit unlivable unloaded unloader unlocked unlocking unlovable " +
    "unloved unlovely unloving unluckily unlucky unmade unmanaged unmanned unmapped unmarked " +
    "unmasked unmasking unmatched unmindful unmixable unmixed unmolded unmoral unmovable unmoved " +
    "unmoving unnamable unnamed unnatural unneeded unnerve unnerving unnoticed unopened unopposed " +
    "unpack unpadded unpaid unpainted unpaired unpaved unpeeled unpicked unpiloted unpinned " +
    "unplanned unplanted unpleased unpledged unplowed unplug unpopular unproven unquote unranked " +
    "unrated unraveled unreached unread unreal unreeling unrefined unrelated unrented unrest " +
    "unretired unrevised unrigged unripe unrivaled unroasted unrobed unroll unruffled unruly " +
    "unrushed unsaddle unsafe unsaid unsalted unsaved unsavory unscathed unscented unscrew " +
    "unsealed unseated unsecured unseeing unseemly unseen unselect unselfish unsent unsettled " +
    "unshackle unshaken unshaved unshaven unsheathe unshipped unsightly unsigned unskilled unsliced " +
    "unsmooth unsnap unsocial unsoiled unsold unsolved unsorted unspoiled unspoken unstable " +
    "unstaffed unstamped unsteady unsterile unstirred unstitch unstopped unstuck unstuffed unstylish " +
    "unsubtle unsubtly unsuited unsure unsworn untagged untainted untaken untamed untangled " +
    "untapped untaxed unthawed unthread untidy untie until untimed untimely untitled " +
    "untoasted untold untouched untracked untrained untreated untried untrimmed untrue untruth " +
    "unturned untwist untying unusable unused unusual unvalued unvaried unvarying unveiled " +
    "unveiling unvented unviable unvisited unvocal unwanted unwarlike unwary unwashed unwatched " +
    "unweave unwed unwelcome unwell unwieldy unwilling unwind unwired unwitting unwomanly " +
    "unworldly unworn unworried unworthy unwound unwoven unwrapped unwritten unzip upbeat " +
    "upchuck upcoming upcountry update upfront upgrade upheaval upheld uphill uphold " +
    "uplifted uplifting upload upon upper upright uprising upriver uproar uproot " +
    "upscale upside upstage upstairs upstart upstate upstream upstroke upswing uptake " +
    "uptight uptown upturned upward upwind uranium urban urchin urethane urgency " +
    "urgent urging urologist urology usable usage useable used uselessly user " +
    "usher usual utensil utility utilize utmost utopia utter vacancy vacant " +
    "vacate vacation vagabond vagrancy vagrantly vaguely vagueness valiant valid valium " +
    "valley valuables value vanilla vanish vanity vanquish vantage vaporizer variable " +
    "variably varied variety various varmint varnish varsity varying vascular vaseline " +
    "vastly vastness veal vegan veggie vehicular velcro velocity velvet vendetta " +
    "vending vendor veneering vengeful venomous ventricle venture venue venus verbalize " +
    "verbally verbose verdict verify verse version versus vertebrae vertical vertigo " +
    "very vessel vest veteran veto vexingly viability viable vibes vice " +
    "vicinity victory video viewable viewer viewing viewless viewpoint vigorous village " +
    "villain vindicate vineyard vintage violate violation violator violet violin viper " +
    "viral virtual virtuous virus visa viscosity viscous viselike visible visibly " +
    "vision visiting visitor visor vista vitality vitalize vitally vitamins vivacious " +
    "vividly vividness vixen vocalist vocalize vocally vocation voice voicing void " +
    "volatile volley voltage volumes voter voting voucher vowed vowel voyage " +
    "wackiness wad wafer waffle waged wager wages waggle wagon wake " +
    "waking walk walmart walnut walrus waltz wand wannabe wanted wanting " +
    "wasabi washable washbasin washboard washbowl washcloth washday washed washer washhouse " +
    "washing washout washroom washstand washtub wasp wasting watch water waviness " +
    "waving wavy whacking whacky wham wharf wheat whenever whiff whimsical " +
    "whinny whiny whisking whoever whole whomever whoopee whooping whoops why " +
    "wick widely widen widget widow width wieldable wielder wife wifi " +
    "wikipedia wildcard wildcat wilder wildfire wildfowl wildland wildlife wildly wildness " +
    "willed willfully willing willow willpower wilt wimp wince wincing wind " +
    "wing winking winner winnings winter wipe wired wireless wiring wiry " +
    "wisdom wise wish wisplike wispy wistful wizard wobble wobbling wobbly " +
    "wok wolf wolverine womanhood womankind womanless womanlike womanly womb woof " +
    "wooing wool woozy word work worried worrier worrisome worry worsening " +
    "worshiper worst wound woven wow wrangle wrath wreath wreckage wrecker " +
    "wrecking wrench wriggle wriggly wrinkle wrinkly wrist writing written wrongdoer " +
    "wronged wrongful wrongly wrongness wrought xbox xerox yahoo yam yanking " +
    "yapping yard yarn yeah yearbook yearling yearly yearning yeast yelling " +
    "yelp yen yesterday yiddish yield yin yippee yodel yoga yogurt " +
    "yonder yoyo yoyoing yummy zap zealous zebra zen zeppelin zero " +
    "zestfully zesty zigzagged zipfile zipping zippy zips zit zodiac zombie " +
    "zone zoning zookeeper zoologist zoology zoom"
  ).split(/\s+/).filter(Boolean);

  // -------- Helpers --------

  function utf8(s) {
    return new TextEncoder().encode(s);
  }

  function fromUtf8(bytes) {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function b64urlEncode(bytes) {
    return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  function b64urlDecode(str) {
    return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  // Recursive sorted-keys JSON serializer with no whitespace.
  // NOT JSON.stringify(obj, Object.keys(obj).sort()) — that only sorts top
  // level. This walks the whole tree.
  function canonicalJSON(value) {
    if (value === null || typeof value !== "object") {
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalJSON).join(",") + "]";
    }
    const keys = Object.keys(value).sort();
    const parts = keys.map(function (k) {
      return JSON.stringify(k) + ":" + canonicalJSON(value[k]);
    });
    return "{" + parts.join(",") + "}";
  }

  // -------- v2 helpers --------

  // Compute a friendly "envelope ID" for the vault: SHA-256 hex of the
  // canonical JSON of the full vault. This gives the user a unique name
  // for their box that they can reference in conversation. It is not
  // cryptographically meaningful (the vault already has its own AEAD
  // tag); it is purely a human identifier.
  function computeEnvelopeId(vault) {
    const bytes = utf8(canonicalJSON(vault));
    const digest = sodium.crypto_hash_sha256(bytes);
    return sodium.to_hex(digest);
  }

  // Generate a 4-word passphrase plus 2 random digits. Words come from
  // the 7776-word list above via randombytes_uniform (unbiased), so the
  // phrase carries about 58 bits of entropy (51.7 from the words, 6.6
  // from the digits). The format is deliberately fixed at
  // word-word-word-word-DD so the browser and CLI generators agree.
  // Example output: "gear-unexposed-rerun-scuttle-50" — an illustration
  // only. Never use a phrase that has been printed in documentation.
  function generatePassphrase() {
    const words = [];
    for (let i = 0; i < 4; i++) {
      const idx = sodium.randombytes_uniform(PASSPHRASE_WORDS.length);
      words.push(PASSPHRASE_WORDS[idx]);
    }
    const d1 = sodium.randombytes_uniform(10);
    const d2 = sodium.randombytes_uniform(10);
    return words.join("-") + "-" + d1 + d2;
  }

  // Hand-rolled password strength estimator. Not zxcvbn but adequate
  // for a "too weak / okay / strong / very strong" indicator. Scores by
  // length, character class diversity, word count, and absence of obvious
  // patterns. Scores below MIN_STRENGTH_SCORE block the submit button.
  function passwordStrength(pw) {
    if (!pw || pw.length === 0) {
      return { score: 0, label: "(empty)", hint: "Type a phrase" };
    }
    let score = 0;
    // Length buckets
    if (pw.length >= 8) score += 1;
    if (pw.length >= 12) score += 1;
    if (pw.length >= 16) score += 1;
    if (pw.length >= 24) score += 1;
    // Character class diversity (maxes at 2 for word-based phrases)
    let classes = 0;
    if (/[a-z]/.test(pw)) classes += 1;
    if (/[A-Z]/.test(pw)) classes += 1;
    if (/[0-9]/.test(pw)) classes += 1;
    if (/[^a-zA-Z0-9]/.test(pw)) classes += 1;
    score += Math.min(classes, 2);
    // Bonus for multi-word phrases (separator between letters)
    const wordSeparators = (pw.match(/[\s\-_.]+/g) || []).length;
    if (wordSeparators >= 3) score += 1; // 4+ tokens
    if (wordSeparators >= 4) score += 1; // 5+ tokens
    // Penalties
    if (/(.)\1\1/.test(pw)) score -= 2; // triple-repeat
    if (/^(password|qwerty|123|letmein|admin|secret|welcome)/i.test(pw)) score -= 4;
    if (pw.length < 8) score = Math.min(score, 1); // hard cap short inputs
    // Reject single-token short inputs (one word, no separators, <12 chars)
    if (pw.length < 12 && wordSeparators === 0) score = Math.min(score, 2);
    if (score < 0) score = 0;
    if (score > 7) score = 7;

    // Map raw score to display bucket
    let label, hint;
    if (score <= 1) {
      label = "too weak";
      hint = "A single word is crackable in hours. Use 4+ random words or the generator below.";
    } else if (score <= 2) {
      label = "weak";
      hint = "Still guessable offline. Try 4+ random words.";
    } else if (score <= 4) {
      label = "okay";
      hint = "Usable. Longer or more words would be safer.";
    } else if (score <= 6) {
      label = "strong";
      hint = "Good. Hard to guess.";
    } else {
      label = "very strong";
      hint = "Excellent. This is very hard to crack.";
    }
    return { score: score, label: label, hint: hint };
  }

  // Build the printable recovery sheet text. This is a plain text file
  // the user can save or print. It contains:
  //   - The two things they need to decrypt (file + phrase)
  //   - All the auto-generated values for reference (already in the box)
  //   - Step-by-step instructions for how to decrypt later
  //   - How to verify the page integrity
  // No information is exposed beyond what is in the .vault.json file.
  function buildRecoverySheet(vault, downloadFilename, envelopeId) {
    const lines = [];
    function L(s) { lines.push(s); }
    function HR() { lines.push("=".repeat(54)); }
    function HR2() { lines.push("-".repeat(54)); }
    const isV2 = vault.schema === SCHEMA_V2;
    HR();
    L("BRY-NFET-SX VAULT  RECOVERY SHEET");
    HR();
    L("");
    L("Locked at: " + vault.created_at);
    L("Made on:   secure.imagineqira.com/chat");
    L("");
    HR2();
    L("TO OPEN THIS LATER, YOU NEED TWO THINGS:");
    HR2();
    L("");
    L("  1. THE LOCKED BOX FILE");
    L("     File name:  " + downloadFilename);
    L("     Save this file. Email it to yourself. Put it on a USB drive.");
    L("     The file is in your downloads folder.");
    L("");
    L("  2. YOUR SECRET PHRASE");
    L("     This is the phrase you typed.");
    L("     We do not know it. We do not store it.");
    L("     If you forget it, the box CANNOT be opened. There is no recovery.");
    L("");
    HR2();
    L("EVERYTHING BELOW IS ALREADY INSIDE THE BOX.");
    L("You do NOT need to save it separately.");
    L("It is here only for your records.");
    HR2();
    L("");
    L("  Box name (envelope ID):");
    L("      " + envelopeId);
    L("");
    L("  Box style:         " + vault.schema);
    L("  Made by version:   " + vault.version);
    L("  Mode:              " + (vault.mode === "share" ? "share with someone" : "just for yourself"));
    L("");
    L("  Lock recipe:");
    if (isV2) {
      L("      Wrap (vault key): " + vault.wrap.algorithm + " (24-byte nonce, 16-byte tag)");
      L("      Content:          " + vault.content.algorithm + " (24-byte nonce, 16-byte tag)");
    } else {
      L("      Encryption:    " + vault.aead.algorithm + " (24-byte nonce, 16-byte tag)");
    }
    L("      Phrase mix:    " + vault.kdf.algorithm + " (work units " + vault.kdf.opslimit + ", memory " + Math.round(vault.kdf.memlimit / 1024 / 1024) + " MiB)");
    L("");
    L("  Your scramble code (salt, base64url):");
    L("      " + vault.kdf.salt);
    L("");
    if (isV2) {
      L("  Wrap nonce (base64url):");
      L("      " + vault.wrap.nonce);
      L("");
      L("  Wrapped vault key (base64url):");
      const wk = vault.wrap.wrapped_key;
      for (let i = 0; i < wk.length; i += 64) {
        L("      " + wk.slice(i, i + 64));
      }
      L("");
      L("  Content nonce (base64url):");
      L("      " + vault.content.nonce);
      L("");
      L("  Encrypted message (ciphertext, base64url):");
      const ct = vault.content.ciphertext;
      for (let i = 0; i < ct.length; i += 64) {
        L("      " + ct.slice(i, i + 64));
      }
    } else {
      L("  Your secret number (nonce, base64url):");
      L("      " + vault.aead.nonce);
      L("");
      L("  Encrypted message (ciphertext, base64url):");
      const ct = vault.aead.ciphertext;
      for (let i = 0; i < ct.length; i += 64) {
        L("      " + ct.slice(i, i + 64));
      }
    }
    L("");
    HR2();
    L("HOW TO OPEN THIS BOX AGAIN:");
    HR2();
    L("");
    L("  1. Go to:    https://secure.imagineqira.com/chat");
    L('  2. Drop EITHER the .vault.json file OR this recovery sheet onto');
    L("     the page. (This sheet contains the full box at the bottom.)");
    L("  3. Type your secret phrase.");
    L('  4. Click "Open it!"');
    L("");
    HR2();
    L("THE LOCKED BOX (machine-readable copy)");
    HR2();
    L("");
    L("If you lost the .vault.json file, you can paste this entire recovery");
    L("sheet into the Open box on the page. The page will find the box");
    L("content between the markers below automatically.");
    L("");
    L("----- BEGIN BRY-NFET-SX VAULT -----");
    const vaultLines = JSON.stringify(vault, null, 2).split("\n");
    vaultLines.forEach(function (vl) { L(vl); });
    L("----- END BRY-NFET-SX VAULT -----");
    L("");
    HR2();
    L("HOW TO VERIFY THIS PAGE IS HONEST:");
    HR2();
    L("");
    L("  1. Go to:    https://secure.imagineqira.com/verify");
    L("  2. Compare the SHA-256 of /chat/chat.js and /chat/sodium.js");
    L("     against the signed integrity record.");
    L("  3. If they match, the JavaScript is the published, signed version.");
    L("");
    HR();
    return lines.join("\n") + "\n";
  }

  function downloadRecoverySheet(vault, downloadFilename, envelopeId) {
    const text = buildRecoverySheet(vault, downloadFilename, envelopeId);
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace("T", "_").replace("Z", "");
    a.href = url;
    a.download = "vault-recovery-" + stamp + ".txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // Build the canonical V1 AAD bytes. Binds schema, version, created_at,
  // mode, kdf{*}, aead{algorithm,nonce}. Used for legacy V1 decryption.
  function buildAADV1(vault) {
    const aadObj = {
      aead: {
        algorithm: vault.aead.algorithm,
        nonce: vault.aead.nonce,
      },
      created_at: vault.created_at,
      kdf: {
        algorithm: vault.kdf.algorithm,
        memlimit: vault.kdf.memlimit,
        opslimit: vault.kdf.opslimit,
        salt: vault.kdf.salt,
      },
      mode: vault.mode,
      schema: vault.schema,
      version: vault.version,
    };
    return utf8(canonicalJSON(aadObj));
  }

  // Build the canonical V2 AAD bytes. Binds every piece of metadata
  // EXCEPT the wrapped_key and ciphertext themselves: schema, version,
  // created_at, mode, kdf{*}, wrap{algorithm,nonce}, content{algorithm,
  // nonce}. This same AAD is used for BOTH the wrap AEAD operation and
  // the content AEAD operation, so tampering with any bound field (salt,
  // kdf params, either nonce, either algorithm string, mode, created_at,
  // schema, version) breaks at least one of the two AEAD tags on decrypt.
  function buildAADV2(vault) {
    const aadObj = {
      content: {
        algorithm: vault.content.algorithm,
        nonce: vault.content.nonce,
      },
      created_at: vault.created_at,
      kdf: {
        algorithm: vault.kdf.algorithm,
        memlimit: vault.kdf.memlimit,
        opslimit: vault.kdf.opslimit,
        salt: vault.kdf.salt,
      },
      mode: vault.mode,
      schema: vault.schema,
      version: vault.version,
      wrap: {
        algorithm: vault.wrap.algorithm,
        nonce: vault.wrap.nonce,
      },
    };
    return utf8(canonicalJSON(aadObj));
  }

  // -------- Validation --------

  function enforceKdfCaps(kdf) {
    if (!kdf || typeof kdf !== "object") {
      throw new Error("Vault malformed: missing kdf section");
    }
    if (kdf.algorithm !== KDF_ALG) {
      throw new Error("Unsupported KDF algorithm: " + kdf.algorithm);
    }
    if (
      typeof kdf.opslimit !== "number" ||
      kdf.opslimit < MIN_OPSLIMIT ||
      kdf.opslimit > MAX_OPSLIMIT
    ) {
      throw new Error(
        "KDF opslimit out of range (" + MIN_OPSLIMIT + "-" + MAX_OPSLIMIT + ")"
      );
    }
    if (
      typeof kdf.memlimit !== "number" ||
      kdf.memlimit < MIN_MEMLIMIT ||
      kdf.memlimit > MAX_MEMLIMIT
    ) {
      throw new Error(
        "KDF memlimit out of range (" +
          (MIN_MEMLIMIT / 1024 / 1024) +
          "-" +
          (MAX_MEMLIMIT / 1024 / 1024) +
          " MiB)"
      );
    }
    if (typeof kdf.salt !== "string") {
      throw new Error("Vault malformed: kdf.salt must be a string");
    }
  }

  function validateCommonVaultFields(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (typeof vault.version !== "string") {
      throw new Error("Vault malformed: missing version");
    }
    if (typeof vault.created_at !== "string") {
      throw new Error("Vault malformed: missing created_at");
    }
    if (vault.mode !== "self" && vault.mode !== "share") {
      throw new Error('Vault malformed: mode must be "self" or "share"');
    }
    enforceKdfCaps(vault.kdf);
  }

  function validateVaultSchemaV1(vault) {
    validateCommonVaultFields(vault);
    if (vault.schema !== SCHEMA_V1) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema + '" (expected ' + SCHEMA_V1 + ")"
      );
    }
    if (!vault.aead || vault.aead.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported AEAD algorithm: " + (vault.aead && vault.aead.algorithm)
      );
    }
    if (typeof vault.aead.nonce !== "string") {
      throw new Error("Vault malformed: missing aead.nonce");
    }
    if (typeof vault.aead.ciphertext !== "string") {
      throw new Error("Vault malformed: missing aead.ciphertext");
    }
  }

  function validateVaultSchemaV2(vault) {
    validateCommonVaultFields(vault);
    if (vault.schema !== SCHEMA_V2) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema + '" (expected ' + SCHEMA_V2 + ")"
      );
    }
    if (!vault.wrap || vault.wrap.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported wrap algorithm: " + (vault.wrap && vault.wrap.algorithm)
      );
    }
    if (typeof vault.wrap.nonce !== "string") {
      throw new Error("Vault malformed: missing wrap.nonce");
    }
    if (typeof vault.wrap.wrapped_key !== "string") {
      throw new Error("Vault malformed: missing wrap.wrapped_key");
    }
    if (!vault.content || vault.content.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported content algorithm: " + (vault.content && vault.content.algorithm)
      );
    }
    if (typeof vault.content.nonce !== "string") {
      throw new Error("Vault malformed: missing content.nonce");
    }
    if (typeof vault.content.ciphertext !== "string") {
      throw new Error("Vault malformed: missing content.ciphertext");
    }
  }

  // Qira Notify uses libsodium's canonical alg name; Vault uses
  // our brand-specific title-case. Both refer to the same AEAD.
  const NOTIFY_AEAD_ALG = "xchacha20poly1305-ietf";

  // Qira Notify V1 validator. Structurally V2-shaped but no `mode`
  // or `version` fields, and it carries its own AAD as literal
  // strings in `wrap.aad` / `content.aad`. Algorithm strings use
  // the libsodium canonical naming (lowercase, `-ietf`) rather
  // than the vault's title-case.
  function validateVaultSchemaQiraNotifyV1(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema !== SCHEMA_QIRA_NOTIFY_V1) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema +
        '" (expected ' + SCHEMA_QIRA_NOTIFY_V1 + ")"
      );
    }
    if (typeof vault.created_at !== "string") {
      throw new Error("Notify envelope malformed: missing created_at");
    }
    enforceKdfCaps(vault.kdf);
    if (!vault.wrap || vault.wrap.algorithm !== NOTIFY_AEAD_ALG) {
      throw new Error(
        "Unsupported wrap algorithm: " + (vault.wrap && vault.wrap.algorithm)
      );
    }
    if (typeof vault.wrap.aad !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.aad");
    }
    if (typeof vault.wrap.nonce !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.nonce");
    }
    if (typeof vault.wrap.wrapped_key !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.wrapped_key");
    }
    if (!vault.content || vault.content.algorithm !== NOTIFY_AEAD_ALG) {
      throw new Error(
        "Unsupported content algorithm: " + (vault.content && vault.content.algorithm)
      );
    }
    if (typeof vault.content.aad !== "string") {
      throw new Error("Notify envelope malformed: missing content.aad");
    }
    if (typeof vault.content.nonce !== "string") {
      throw new Error("Notify envelope malformed: missing content.nonce");
    }
    if (typeof vault.content.ciphertext !== "string") {
      throw new Error("Notify envelope malformed: missing content.ciphertext");
    }
  }

  // Dispatch validator — chooses V1, V2, or Notify-V1 based on schema.
  function validateVaultSchema(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema === SCHEMA_V2) return validateVaultSchemaV2(vault);
    if (vault.schema === SCHEMA_V1) return validateVaultSchemaV1(vault);
    if (vault.schema === SCHEMA_QIRA_NOTIFY_V1) {
      return validateVaultSchemaQiraNotifyV1(vault);
    }
    throw new Error(
      'Unsupported vault schema: "' + vault.schema +
      '" (expected ' + SCHEMA_V2 + ", " + SCHEMA_V1 + ", or " +
      SCHEMA_QIRA_NOTIFY_V1 + ")"
    );
  }

  // -------- Encrypt / Decrypt --------
  //
  // Two schemas are supported:
  //   V1 (legacy) — direct encryption of plaintext with a password-derived
  //                 key. Still readable for backward compat; not produced
  //                 for new vaults.
  //   V2 (current) — random vault_key wraps the data, wrap_key (derived
  //                  from password) wraps the vault_key. Same AEAD
  //                  primitive for both layers. Same AAD for both layers.
  //
  // Top-level encryptVault() always produces V2. Top-level decryptVault()
  // dispatches on vault.schema so old V1 boxes still open cleanly.

  // ---- V1 (legacy) ----

  function encryptVaultV1(opts) {
    const plaintext = opts.plaintext;
    const password = opts.password;
    const mode = opts.mode;
    const salt = opts.salt || sodium.randombytes_buf(SALT_BYTES);
    const nonce = opts.nonce || sodium.randombytes_buf(NONCE_BYTES);
    const opslimit = opts.opslimit || DEFAULT_OPSLIMIT;
    const memlimit = opts.memlimit || DEFAULT_MEMLIMIT;

    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw new Error("Type a message before encrypting");
    }
    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type a phrase before encrypting");
    }
    if (mode !== "self" && mode !== "share") {
      throw new Error("Pick a mode first");
    }
    if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
      throw new Error("Invalid salt (must be " + SALT_BYTES + " bytes)");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) {
      throw new Error("Invalid nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
      throw new Error("opslimit out of range");
    }
    if (memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
      throw new Error("memlimit out of range");
    }

    const ptBytes = utf8(plaintext);
    if (ptBytes.length > MAX_PLAINTEXT_BYTES) {
      throw new Error(
        "Message too large (max " + (MAX_PLAINTEXT_BYTES / 1024) + " KiB)"
      );
    }

    const pwBytes = utf8(password);
    const key = sodium.crypto_pwhash(
      KEY_BYTES,
      pwBytes,
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const vault = {
      schema: SCHEMA_V1,
      version: VERSION,
      created_at: new Date().toISOString(),
      mode: mode,
      kdf: {
        algorithm: KDF_ALG,
        opslimit: opslimit,
        memlimit: memlimit,
        salt: b64urlEncode(salt),
      },
      aead: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(nonce),
        ciphertext: "", // filled below
      },
    };

    const aad = buildAADV1(vault);

    let ct;
    try {
      ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ptBytes, aad, null, nonce, key
      );
    } finally {
      sodium.memzero(key);
    }
    vault.aead.ciphertext = b64urlEncode(ct);
    return vault;
  }

  function decryptVaultV1(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaV1(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const nonce = b64urlDecode(vault.aead.nonce);
    const ct = b64urlDecode(vault.aead.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Vault malformed: salt length");
    if (nonce.length !== NONCE_BYTES) throw new Error("Vault malformed: nonce length");
    if (ct.length === 0) throw new Error("Vault malformed: empty ciphertext");
    if (ct.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Vault too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    const pwBytes = utf8(password);
    const key = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const aad = buildAADV1(vault);

    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ct, aad, nonce, key
      );
    } catch (err) {
      sodium.memzero(key);
      throw new Error("Could not decrypt: wrong phrase or tampered vault");
    }
    sodium.memzero(key);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8 (vault may be corrupted)");
    }
  }

  // ---- V2 (current) ----

  function encryptVaultV2(opts) {
    const plaintext = opts.plaintext;
    const password = opts.password;
    const mode = opts.mode;
    // Caller-supplied randomness so the live UI displays what was used.
    // Fallback to fresh random values if not supplied (used by self-test).
    const salt = opts.salt || sodium.randombytes_buf(SALT_BYTES);
    const wrapNonce = opts.wrapNonce || sodium.randombytes_buf(NONCE_BYTES);
    const contentNonce = opts.contentNonce || sodium.randombytes_buf(NONCE_BYTES);
    const vaultKey = opts.vaultKey || sodium.randombytes_buf(KEY_BYTES);
    const opslimit = opts.opslimit || DEFAULT_OPSLIMIT;
    const memlimit = opts.memlimit || DEFAULT_MEMLIMIT;

    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw new Error("Type a message before encrypting");
    }
    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type a phrase before encrypting");
    }
    if (mode !== "self" && mode !== "share") {
      throw new Error("Pick a mode first");
    }
    if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
      throw new Error("Invalid salt (must be " + SALT_BYTES + " bytes)");
    }
    if (!(wrapNonce instanceof Uint8Array) || wrapNonce.length !== NONCE_BYTES) {
      throw new Error("Invalid wrap nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (!(contentNonce instanceof Uint8Array) || contentNonce.length !== NONCE_BYTES) {
      throw new Error("Invalid content nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) {
      throw new Error("Invalid vault_key (must be " + KEY_BYTES + " bytes)");
    }
    if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
      throw new Error("opslimit out of range");
    }
    if (memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
      throw new Error("memlimit out of range");
    }

    const ptBytes = utf8(plaintext);
    if (ptBytes.length > MAX_PLAINTEXT_BYTES) {
      throw new Error(
        "Message too large (max " + (MAX_PLAINTEXT_BYTES / 1024) + " KiB)"
      );
    }

    // Derive wrap_key from the password. This is the ONLY role the password
    // plays in V2 — it unlocks the vault_key, which in turn unlocks the data.
    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      opslimit, memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    // Build the vault skeleton so we can compute the shared AAD once.
    const vault = {
      schema: SCHEMA_V2,
      version: VERSION,
      created_at: new Date().toISOString(),
      mode: mode,
      kdf: {
        algorithm: KDF_ALG,
        opslimit: opslimit,
        memlimit: memlimit,
        salt: b64urlEncode(salt),
      },
      wrap: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(wrapNonce),
        wrapped_key: "", // filled below
      },
      content: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(contentNonce),
        ciphertext: "", // filled below
      },
    };

    const aad = buildAADV2(vault);

    // Step 1: wrap vault_key with wrap_key (AEAD over the vault_key bytes).
    let wrappedKey;
    try {
      wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        vaultKey, aad, null, wrapNonce, wrapKey
      );
    } finally {
      sodium.memzero(wrapKey);
    }
    vault.wrap.wrapped_key = b64urlEncode(wrappedKey);

    // Step 2: encrypt plaintext with vault_key (AEAD over the plaintext).
    let contentCt;
    try {
      contentCt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ptBytes, aad, null, contentNonce, vaultKey
      );
    } finally {
      sodium.memzero(vaultKey);
    }
    vault.content.ciphertext = b64urlEncode(contentCt);

    return vault;
  }

  function decryptVaultV2(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaV2(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const wrapNonce = b64urlDecode(vault.wrap.nonce);
    const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
    const contentNonce = b64urlDecode(vault.content.nonce);
    const contentCt = b64urlDecode(vault.content.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Vault malformed: salt length");
    if (wrapNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: wrap nonce length");
    if (contentNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: content nonce length");
    // wrapped_key = 32-byte vault_key + 16-byte Poly1305 tag = 48 bytes exactly
    if (wrappedKey.length !== KEY_BYTES + 16) {
      throw new Error("Vault malformed: wrapped_key length (got " + wrappedKey.length + ")");
    }
    if (contentCt.length === 0) throw new Error("Vault malformed: empty ciphertext");
    if (contentCt.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Vault too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    // Derive wrap_key from the password.
    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const aad = buildAADV2(vault);

    // Step 1: unwrap vault_key. If this fails, the phrase is wrong OR the
    // wrap metadata has been tampered with. Either way, the user-visible
    // error is the same.
    let vaultKey;
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, wrappedKey, aad, wrapNonce, wrapKey
      );
    } catch (err) {
      sodium.memzero(wrapKey);
      throw new Error("Could not decrypt: wrong phrase or tampered vault");
    }
    sodium.memzero(wrapKey);

    if (vaultKey.length !== KEY_BYTES) {
      sodium.memzero(vaultKey);
      throw new Error("Vault malformed: unwrapped vault_key is not " + KEY_BYTES + " bytes");
    }

    // Step 2: decrypt content with vault_key. If the unwrap succeeded, the
    // phrase was correct — so a failure here means the ciphertext block was
    // modified independently from the wrap. Report it distinctly.
    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, contentCt, aad, contentNonce, vaultKey
      );
    } catch (err) {
      sodium.memzero(vaultKey);
      throw new Error("Could not decrypt: vault content was tampered with");
    }
    sodium.memzero(vaultKey);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8 (vault may be corrupted)");
    }
  }

  // -------- Qira Notify V1 decrypt --------
  //
  // A Notify envelope is structurally V2-shaped but its AAD is the
  // envelope's literal `wrap.aad` / `content.aad` strings, not a
  // canonical-JSON binding of the metadata. Same AEAD + KDF as V2;
  // only the AAD differs.
  //
  // Read-only: QEV never produces Notify envelopes — this path
  // exists so a user who pastes a Notify inbox JSON can open it
  // with their phrase in the Vault tab, no extra tooling required.
  function decryptVaultQiraNotifyV1(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaQiraNotifyV1(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const wrapNonce = b64urlDecode(vault.wrap.nonce);
    const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
    const contentNonce = b64urlDecode(vault.content.nonce);
    const contentCt = b64urlDecode(vault.content.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Notify envelope malformed: salt length");
    if (wrapNonce.length !== NONCE_BYTES) throw new Error("Notify envelope malformed: wrap nonce length");
    if (contentNonce.length !== NONCE_BYTES) throw new Error("Notify envelope malformed: content nonce length");
    if (wrappedKey.length !== KEY_BYTES + 16) {
      throw new Error("Notify envelope malformed: wrapped_key length (got " + wrappedKey.length + ")");
    }
    if (contentCt.length === 0) throw new Error("Notify envelope malformed: empty ciphertext");
    if (contentCt.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Notify envelope too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const wrapAad = utf8(vault.wrap.aad);
    const contentAad = utf8(vault.content.aad);

    let vaultKey;
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, wrappedKey, wrapAad, wrapNonce, wrapKey
      );
    } catch (err) {
      sodium.memzero(wrapKey);
      throw new Error("Could not decrypt: wrong phrase or tampered envelope");
    }
    sodium.memzero(wrapKey);

    if (vaultKey.length !== KEY_BYTES) {
      sodium.memzero(vaultKey);
      throw new Error("Notify envelope malformed: unwrapped vault_key is not " + KEY_BYTES + " bytes");
    }

    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, contentCt, contentAad, contentNonce, vaultKey
      );
    } catch (err) {
      sodium.memzero(vaultKey);
      throw new Error("Could not decrypt: Notify envelope content was tampered with");
    }
    sodium.memzero(vaultKey);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8");
    }
  }

  // ---- Top-level dispatch ----

  // Encrypt always produces V2. There is no reason to produce new V1 vaults.
  function encryptVault(opts) {
    return encryptVaultV2(opts);
  }

  // Decrypt dispatches on the schema string so legacy V1 boxes still
  // open AND Qira Notify envelopes open too.
  function decryptVault(opts) {
    const vault = opts && opts.vault;
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema === SCHEMA_V2) return decryptVaultV2(opts);
    if (vault.schema === SCHEMA_V1) return decryptVaultV1(opts);
    if (vault.schema === SCHEMA_QIRA_NOTIFY_V1) {
      return decryptVaultQiraNotifyV1(opts);
    }
    throw new Error(
      'Unsupported vault schema: "' + vault.schema +
      '" (expected ' + SCHEMA_V2 + ", " + SCHEMA_V1 + ", or " +
      SCHEMA_QIRA_NOTIFY_V1 + ")"
    );
  }

  // -------- Self-test --------
  // Exercises the full encrypt/decrypt paths for BOTH V1 and V2 before
  // the UI is enabled. Catches "WASM did not load", "library is broken",
  // any regression in either vault format, and any break in the dispatch
  // logic. Uses the Quick lock (opslimit=1, 32 MiB) so load time stays
  // under ~1s on modest hardware; production encrypts still use whatever
  // preset the user selects.
  function runSelfTest() {
    const testPlain = "self-test: hello world";
    const testPassword = "self-test-phrase-only";
    const quick = LOCK_PRESETS.quick;

    // ---- V2 round-trip (primary path) ----
    const v2 = encryptVaultV2({
      plaintext: testPlain,
      password: testPassword,
      mode: "self",
      opslimit: quick.opslimit,
      memlimit: quick.memlimit,
    });
    if (v2.schema !== SCHEMA_V2) {
      throw new Error("Self-test: V2 encrypt produced wrong schema");
    }
    const v2Round = decryptVault({ vault: v2, password: testPassword });
    if (v2Round !== testPlain) {
      throw new Error("Self-test: V2 round-trip mismatch");
    }
    // Wrong-phrase negative test — unwrap must fail cleanly.
    let v2WrongPwOk = false;
    try {
      decryptVault({ vault: v2, password: "wrong-phrase" });
    } catch (e) {
      v2WrongPwOk = true;
    }
    if (!v2WrongPwOk) {
      throw new Error("Self-test: V2 wrong-phrase check failed");
    }
    // Tamper test — flip a byte in the content ciphertext and confirm
    // the content AEAD tag rejects it. This catches any regression that
    // lets a partially-tampered vault silently decrypt.
    const tampered = JSON.parse(JSON.stringify(v2));
    const ctBytes = b64urlDecode(tampered.content.ciphertext);
    ctBytes[0] = ctBytes[0] ^ 0x01;
    tampered.content.ciphertext = b64urlEncode(ctBytes);
    let v2TamperOk = false;
    try {
      decryptVault({ vault: tampered, password: testPassword });
    } catch (e) {
      v2TamperOk = true;
    }
    if (!v2TamperOk) {
      throw new Error("Self-test: V2 tamper check failed");
    }

    // ---- V1 round-trip (legacy path — backward compat) ----
    const v1 = encryptVaultV1({
      plaintext: testPlain,
      password: testPassword,
      mode: "self",
      opslimit: quick.opslimit,
      memlimit: quick.memlimit,
    });
    if (v1.schema !== SCHEMA_V1) {
      throw new Error("Self-test: V1 encrypt produced wrong schema");
    }
    const v1Round = decryptVault({ vault: v1, password: testPassword });
    if (v1Round !== testPlain) {
      throw new Error("Self-test: V1 legacy round-trip mismatch");
    }
  }

  // -------- DOM wiring --------

  let currentMode = "self";
  // Live values displayed on the encrypt form. For V2 vaults we need
  // two separate nonces: one for wrapping the vault_key, one for the
  // content. The user-visible "secret number" knob shows the wrap nonce
  // (the public-facing one) and the content nonce is auto-generated
  // fresh at submit time.
  let currentNonce = null; // used as the V2 wrap nonce
  let currentSalt = null;
  let currentPresetKey = DEFAULT_PRESET_KEY;

  function $(id) {
    return document.getElementById(id);
  }

  function getCurrentLockStrength() {
    return LOCK_PRESETS[currentPresetKey] || LOCK_PRESETS[DEFAULT_PRESET_KEY];
  }

  function refreshNonceDisplay() {
    const el = $("vault-knob-nonce-value");
    if (el && currentNonce) {
      el.textContent = b64urlEncode(currentNonce);
    }
  }
  function refreshSaltDisplay() {
    const el = $("vault-knob-salt-value");
    if (el && currentSalt) {
      el.textContent = b64urlEncode(currentSalt);
    }
  }
  function regenerateNonce() {
    currentNonce = sodium.randombytes_buf(NONCE_BYTES);
    refreshNonceDisplay();
  }
  function regenerateSalt() {
    currentSalt = sodium.randombytes_buf(SALT_BYTES);
    refreshSaltDisplay();
  }
  function refreshLockStrengthButtons() {
    Object.keys(LOCK_PRESETS).forEach(function (key) {
      const btn = $("vault-lock-preset-" + key);
      if (btn) {
        btn.classList.toggle("vault-preset-active", key === currentPresetKey);
      }
    });
  }
  function setLockStrength(key) {
    if (LOCK_PRESETS[key]) {
      currentPresetKey = key;
      refreshLockStrengthButtons();
    }
  }
  // Track whether the self-test has enabled the form at least once. We
  // only gate submit on strength AFTER init completes, so a failed self-
  // test still wins (submit stays disabled for the right reason).
  let formsEnabledAfterSelfTest = false;

  function refreshPasswordStrength() {
    const input = $("vault-encrypt-password");
    const meter = $("vault-pw-strength");
    const submit = $("vault-encrypt-submit");
    const hintEl = $("vault-pw-hint");
    if (!input || !meter) return;
    const result = passwordStrength(input.value);
    const fill = meter.querySelector(".vault-pw-strength-fill");
    const label = meter.querySelector(".vault-pw-strength-label");
    if (fill) {
      const pct = Math.round((result.score / 7) * 100);
      fill.style.width = pct + "%";
      let color = "#dc2626";
      if (result.score >= MIN_STRENGTH_SCORE) color = "#d97706";
      if (result.score >= 5) color = "#0d7a4f";
      fill.style.background = color;
    }
    if (label) {
      label.textContent = result.label;
    }
    // Gate the submit button on strength. Only takes effect after the
    // self-test has run and enabled the forms once; before that, submit
    // stays disabled by init().
    if (submit && formsEnabledAfterSelfTest) {
      const weak = result.score < MIN_STRENGTH_SCORE;
      submit.disabled = weak;
      submit.title = weak
        ? "Phrase is too weak. Use 4+ random words or the generator button."
        : "";
    }
    // Live per-field hint text (shows weak-phrase guidance inline).
    if (hintEl) {
      if (input.value.length === 0) {
        hintEl.textContent = "";
      } else {
        hintEl.textContent = result.hint;
      }
      hintEl.className = "vault-pw-hint " +
        (result.score < MIN_STRENGTH_SCORE ? "vault-pw-hint-weak" : "vault-pw-hint-ok");
    }
  }

  function wireKnobControls() {
    // Regenerate buttons
    const regenNonce = $("vault-regen-nonce");
    if (regenNonce) regenNonce.addEventListener("click", regenerateNonce);
    const regenSalt = $("vault-regen-salt");
    if (regenSalt) regenSalt.addEventListener("click", regenerateSalt);

    // Lock strength preset buttons
    Object.keys(LOCK_PRESETS).forEach(function (key) {
      const btn = $("vault-lock-preset-" + key);
      if (btn) {
        btn.addEventListener("click", function () { setLockStrength(key); });
      }
    });

    // Passphrase generator
    const genBtn = $("vault-pw-generate");
    if (genBtn) {
      genBtn.addEventListener("click", function () {
        const input = $("vault-encrypt-password");
        if (!input) return;
        input.type = "text"; // briefly show the generated passphrase
        input.value = generatePassphrase();
        refreshPasswordStrength();
        // Hide it again after a few seconds so it doesn't sit on screen
        setTimeout(function () {
          if (input.type === "text") {
            // Keep visible until user toggles or clears
          }
        }, 0);
      });
    }

    // Password strength meter live update
    const pwInput = $("vault-encrypt-password");
    if (pwInput) {
      pwInput.addEventListener("input", refreshPasswordStrength);
    }

    // Tooltip click-to-reveal (CSS handles styling, JS toggles a class)
    document.querySelectorAll("[data-vault-tooltip-toggle]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        ev.preventDefault();
        const targetId = el.getAttribute("data-vault-tooltip-toggle");
        const target = $(targetId);
        if (target) {
          target.classList.toggle("vault-tooltip-open");
        }
      });
    });

    // Initialize displays
    refreshLockStrengthButtons();
    refreshPasswordStrength();
  }

  function setStatus(elId, msg, kind) {
    const el = $(elId);
    if (!el) return;
    el.textContent = msg;
    el.className =
      "vault-status" + (kind ? " vault-status-" + kind : "");
  }

  function setMode(mode) {
    currentMode = mode;
    const selfBtn = $("vault-mode-self");
    const shareBtn = $("vault-mode-share");
    if (selfBtn) selfBtn.classList.toggle("vault-mode-active", mode === "self");
    if (shareBtn) shareBtn.classList.toggle("vault-mode-active", mode === "share");
    const headline = $("vault-mode-headline");
    const helper = $("vault-mode-helper");
    if (mode === "self") {
      if (headline) headline.textContent = "Encrypt a note for yourself";
      if (helper) {
        helper.textContent =
          "Type a message and a password. Save the vault file. Remember the password. You can decrypt it later on any device.";
      }
    } else {
      if (headline) headline.textContent = "Send a secret to someone";
      if (helper) {
        helper.textContent =
          "Share a password with the recipient on a separate channel (call them, text them). Encrypt with that password. Send them the vault file by any means. They paste the file and the password to read it.";
      }
    }
  }

  function downloadVault(vault) {
    const json = JSON.stringify(vault, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date()
      .toISOString()
      .replace(/[:.]/g, "-")
      .replace("T", "_")
      .replace("Z", "");
    a.href = url;
    a.download = "vault-" + stamp + ".vault.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  function copyVaultText(vault) {
    const json = canonicalJSON(vault);
    const enc = b64urlEncode(utf8(json));
    // Use the V2 prefix for new (V2) vaults and the V1 prefix for legacy.
    // Decrypt-side accepts both prefixes regardless.
    const prefix = vault.schema === SCHEMA_V1 ? VAULT_TEXT_PREFIX_V1 : VAULT_TEXT_PREFIX_V2;
    const text = prefix + enc;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return Promise.reject(new Error("Clipboard API not available"));
  }

  // Chat envelope decrypt path. Returns { plaintext, meta } on
  // success, null if the input isn't a chat envelope, or throws a
  // user-friendly Error if the input IS a chat envelope but decryption
  // fails (wrong phrase, malformed payload, etc). The caller catches
  // the throw and surfaces the error to the user.
  function tryDecryptChatEnvelope(raw, phrase) {
    const trimmed = (raw || "").trim();
    if (trimmed.length === 0 || trimmed.charAt(0) !== "{") return null;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      return null;
    }
    if (!parsed || parsed.schema !== "QEV-CHAT-ENVELOPE-V1") return null;
    if (!Array.isArray(parsed.ids) || parsed.ids.length !== 2) {
      throw new Error("Chat envelope missing 'ids' pair");
    }
    if (typeof parsed.nonce !== "string" || typeof parsed.ct !== "string") {
      throw new Error("Chat envelope missing 'nonce' or 'ct'");
    }
    if (typeof phrase !== "string" || phrase.length === 0) {
      throw new Error("Type the shared phrase to decrypt the chat message");
    }
    const ids = parsed.ids
      .map(function (s) { return String(s).toLowerCase(); })
      .sort();
    const contextStr = "QEV-CHAT-V1:" + ids[0] + ":" + ids[1];
    const phraseBytes = new TextEncoder().encode(phrase);
    const contextBytes = new TextEncoder().encode(contextStr);
    const combined = new Uint8Array(phraseBytes.length + contextBytes.length);
    combined.set(phraseBytes);
    combined.set(contextBytes, phraseBytes.length);
    const key = sodium.crypto_generichash(32, combined);
    sodium.memzero(combined);
    sodium.memzero(phraseBytes);
    let nonceBytes;
    let ctBytes;
    try {
      nonceBytes = sodium.from_base64(parsed.nonce, sodium.base64_variants.URLSAFE_NO_PADDING);
      ctBytes = sodium.from_base64(parsed.ct, sodium.base64_variants.URLSAFE_NO_PADDING);
    } catch (e) {
      throw new Error("Chat envelope base64 malformed");
    }
    let ptBytes;
    try {
      ptBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ctBytes, null, nonceBytes, key);
    } catch (e) {
      sodium.memzero(key);
      throw new Error("Wrong phrase (AEAD auth tag mismatch)");
    }
    sodium.memzero(key);
    const plaintext = new TextDecoder().decode(ptBytes);
    sodium.memzero(ptBytes);
    const meta = "Schema: QEV-CHAT-ENVELOPE-V1  |  Participants: " + ids[0].slice(0, 8) + "… ↔ " + ids[1].slice(0, 8) + "…";
    return { plaintext: plaintext, meta: meta };
  }

  function parseVaultInput(raw) {
    const trimmed = (raw || "").trim();
    if (trimmed.length === 0) {
      throw new Error("Paste a vault first");
    }
    // Form 1: recovery sheet — look for the BEGIN/END markers and
    // extract the JSON between them. This lets users drop or paste
    // the recovery .txt file and have it work the same as the
    // .vault.json file.
    const beginMarker = "----- BEGIN BRY-NFET-SX VAULT -----";
    const endMarker = "----- END BRY-NFET-SX VAULT -----";
    const beginIdx = trimmed.indexOf(beginMarker);
    const endIdx = trimmed.indexOf(endMarker);
    if (beginIdx !== -1 && endIdx !== -1 && endIdx > beginIdx) {
      const inner = trimmed
        .slice(beginIdx + beginMarker.length, endIdx)
        .trim();
      try {
        return JSON.parse(inner);
      } catch (e) {
        throw new Error(
          "Recovery sheet found but the embedded vault JSON is malformed"
        );
      }
    }
    // Form 2: single-line text form. Accept either V1 or V2 prefix.
    const textPrefix =
      trimmed.indexOf(VAULT_TEXT_PREFIX_V2) === 0 ? VAULT_TEXT_PREFIX_V2 :
      trimmed.indexOf(VAULT_TEXT_PREFIX_V1) === 0 ? VAULT_TEXT_PREFIX_V1 :
      null;
    if (textPrefix) {
      const b64 = trimmed.slice(textPrefix.length);
      let bytes;
      try {
        bytes = b64urlDecode(b64);
      } catch (e) {
        throw new Error("Vault text format is invalid");
      }
      const jsonStr = fromUtf8(bytes);
      return JSON.parse(jsonStr);
    }
    // Form 3: raw JSON (the .vault.json file)
    try {
      return JSON.parse(trimmed);
    } catch (e) {
      throw new Error(
        "Could not parse vault. Drop the .vault.json file or the recovery sheet .txt file."
      );
    }
  }

  function wireEncryptForm() {
    const form = $("vault-encrypt-form");
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      setStatus("vault-encrypt-status", "Encrypting...", "info");
      const submitBtn = $("vault-encrypt-submit");
      if (submitBtn) submitBtn.disabled = true;
      // Defer the blocking Argon2id call to the next macrotask so the
      // browser can paint the "Encrypting..." message first. Do NOT use
      // requestAnimationFrame — modern browsers throttle rAF to never
      // fire in background/hidden tabs, which would silently freeze the
      // form. setTimeout(fn, 0) runs regardless of tab visibility.
      setTimeout(function () {
        (function () {
          try {
            const message = $("vault-encrypt-message").value;
            const password = $("vault-encrypt-password").value;
            const preset = getCurrentLockStrength();
            // Re-check strength at submit time (belt-and-suspenders —
            // the button gating already catches weak inputs, but this
            // defends against anyone bypassing the disabled attribute).
            const pwCheck = passwordStrength(password);
            if (pwCheck.score < MIN_STRENGTH_SCORE) {
              throw new Error(
                "Phrase is too weak to lock. Use 4+ random words or click the generator button."
              );
            }
            // currentNonce is the V2 wrap nonce (the user-visible one).
            // The content nonce is generated fresh at encrypt time so no
            // two vaults share it even if the user doesn't regenerate.
            const vault = encryptVault({
              plaintext: message,
              password: password,
              mode: currentMode,
              salt: currentSalt,
              wrapNonce: currentNonce,
              opslimit: preset.opslimit,
              memlimit: preset.memlimit,
            });
            // Clear sensitive form fields
            $("vault-encrypt-message").value = "";
            $("vault-encrypt-password").value = "";
            // Compute envelope ID for the result panel + recovery sheet
            const envelopeId = computeEnvelopeId(vault);
            const downloadStamp = new Date().toISOString().slice(0, 10);
            const downloadFilename = "vault-" + downloadStamp + ".vault.json";
            // Regenerate the displayed nonce + salt so the next encrypt
            // doesn't reuse the same values (visible feedback that each
            // box gets its own).
            regenerateNonce();
            regenerateSalt();
            refreshPasswordStrength();
            // Render result
            const resultJson = JSON.stringify(vault, null, 2);
            $("vault-encrypt-result-json").textContent = resultJson;
            const idEl = $("vault-encrypt-result-envelope-id");
            if (idEl) idEl.textContent = envelopeId;
            $("vault-encrypt-result").classList.remove("vault-hidden");
            // Wire result buttons
            $("vault-download-btn").onclick = function () {
              downloadVault(vault);
            };
            $("vault-copy-btn").onclick = function () {
              copyVaultText(vault).then(
                function () {
                  setStatus(
                    "vault-encrypt-status",
                    "Copied vault text to clipboard",
                    "ok"
                  );
                },
                function (err) {
                  setStatus(
                    "vault-encrypt-status",
                    "Could not copy: " + err.message,
                    "err"
                  );
                }
              );
            };
            const recBtn = $("vault-recovery-btn");
            if (recBtn) {
              recBtn.onclick = function () {
                downloadRecoverySheet(vault, downloadFilename, envelopeId);
              };
            }
            setStatus(
              "vault-encrypt-status",
              "Locked! Save the box file and remember your secret phrase.",
              "ok"
            );
          } catch (err) {
            setStatus("vault-encrypt-status", err.message, "err");
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        })();
      }, 0);
    });
  }

  function wireDecryptForm() {
    const form = $("vault-decrypt-form");
    if (!form) return;

    // Drag-and-drop file input
    const dropzone = $("vault-decrypt-dropzone");
    const fileInput = $("vault-decrypt-file");
    if (dropzone) {
      ["dragenter", "dragover"].forEach(function (ev) {
        dropzone.addEventListener(ev, function (e) {
          e.preventDefault();
          dropzone.classList.add("vault-dropzone-hover");
        });
      });
      ["dragleave", "drop"].forEach(function (ev) {
        dropzone.addEventListener(ev, function (e) {
          e.preventDefault();
          dropzone.classList.remove("vault-dropzone-hover");
        });
      });
      dropzone.addEventListener("drop", function (e) {
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length > 0) {
          loadFileIntoTextarea(files[0]);
        }
      });
    }
    if (fileInput) {
      fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files.length > 0) {
          loadFileIntoTextarea(fileInput.files[0]);
        }
      });
    }

    function loadFileIntoTextarea(file) {
      const reader = new FileReader();
      reader.onload = function () {
        $("vault-decrypt-input").value = reader.result;
        setStatus(
          "vault-decrypt-status",
          "Loaded " + file.name + ". Now type the password.",
          "info"
        );
      };
      reader.onerror = function () {
        setStatus("vault-decrypt-status", "Could not read file", "err");
      };
      reader.readAsText(file);
    }

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      setStatus("vault-decrypt-status", "Decrypting...", "info");
      const submitBtn = $("vault-decrypt-submit");
      if (submitBtn) submitBtn.disabled = true;
      // setTimeout (not rAF) — rAF is throttled in background tabs.
      setTimeout(function () {
        (function () {
          try {
            const raw = $("vault-decrypt-input").value;
            const password = $("vault-decrypt-password").value;

            // Chat-envelope fast path. Before attempting vault decode,
            // peek at the trimmed JSON and see if it's a chat envelope
            // copied from a locked conversation. If so, decrypt with
            // the per-chat BLAKE2b(phrase || context) key and bypass
            // the vault Argon2id path entirely. Vault code is never
            // touched — this is a pre-check that only fires for the
            // chat schema string.
            const chatResult = tryDecryptChatEnvelope(raw, password);
            if (chatResult !== null) {
              $("vault-decrypt-password").value = "";
              $("vault-decrypt-result-text").textContent = chatResult.plaintext;
              $("vault-decrypt-result").classList.remove("vault-hidden");
              $("vault-decrypt-result-meta").textContent = chatResult.meta;
              setStatus("vault-decrypt-status", "Chat message decrypted", "ok");
              return;
            }

            const vault = parseVaultInput(raw);
            const plaintext = decryptVault({ vault: vault, password: password });
            // Clear sensitive form fields
            $("vault-decrypt-password").value = "";
            // Render result
            $("vault-decrypt-result-text").textContent = plaintext;
            $("vault-decrypt-result").classList.remove("vault-hidden");
            // Meta line adapts to the schema — Notify envelopes don't
            // have `mode`/`version`, so we show a tailored label for
            // those and skip the missing fields rather than showing
            // "your own note" (wrong) or "vundefined" (ugly).
            const isNotify = vault.schema === SCHEMA_QIRA_NOTIFY_V1;
            const metaParts = [];
            if (isNotify) {
              metaParts.push("Source: Qira Notify encrypted notification");
            } else {
              metaParts.push(
                "Mode: " +
                  (vault.mode === "share" ? "shared with you" : "your own note")
              );
            }
            metaParts.push("Created: " + vault.created_at);
            metaParts.push(
              "Schema: " + vault.schema + (vault.version ? " v" + vault.version : "")
            );
            const meta = metaParts.join("  |  ");
            $("vault-decrypt-result-meta").textContent = meta;
            setStatus("vault-decrypt-status", "Decrypted successfully", "ok");
          } catch (err) {
            setStatus("vault-decrypt-status", err.message, "err");
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        })();
      }, 0);
    });
  }

  function wirePasswordRevealToggles() {
    const toggles = document.querySelectorAll("[data-vault-reveal-target]");
    toggles.forEach(function (toggle) {
      toggle.addEventListener("click", function () {
        const targetId = toggle.getAttribute("data-vault-reveal-target");
        const target = $(targetId);
        if (!target) return;
        if (target.type === "password") {
          target.type = "text";
          toggle.textContent = "Hide";
        } else {
          target.type = "password";
          toggle.textContent = "Show";
        }
      });
    });
  }

  function wireModeChooser() {
    const selfBtn = $("vault-mode-self");
    const shareBtn = $("vault-mode-share");
    if (selfBtn) {
      selfBtn.addEventListener("click", function () {
        setMode("self");
      });
    }
    if (shareBtn) {
      shareBtn.addEventListener("click", function () {
        setMode("share");
      });
    }
    setMode("self");
  }

  function init() {
    if (typeof sodium === "undefined") {
      setStatus(
        "vault-load-status",
        "Crypto library failed to load. Refresh and try again.",
        "err"
      );
      return;
    }
    setStatus("vault-load-status", "Loading crypto module...", "info");
    sodium.ready
      .then(function () {
        try {
          runSelfTest();
        } catch (err) {
          setStatus(
            "vault-load-status",
            "Self-test failed: " + err.message + ". Encryption disabled.",
            "err"
          );
          return;
        }
        // Self-test passed — enable forms.
        // The decrypt submit is enabled unconditionally (users may be
        // opening a vault with any phrase). The encrypt submit is
        // enabled here but then immediately gated by the strength check
        // on the empty password field, so it will re-disable until the
        // user enters a phrase that meets MIN_STRENGTH_SCORE.
        const decryptSubmit = $("vault-decrypt-submit");
        if (decryptSubmit) decryptSubmit.disabled = false;
        const encryptSubmit = $("vault-encrypt-submit");
        if (encryptSubmit) encryptSubmit.disabled = false;
        formsEnabledAfterSelfTest = true;
        setStatus("vault-load-status", "Ready", "ok");
        // Compute initial nonce + salt so the knob displays have values
        // from the first paint.
        regenerateNonce();
        regenerateSalt();
        wireModeChooser();
        wireKnobControls();
        wireEncryptForm();
        wireDecryptForm();
        wirePasswordRevealToggles();
        // Apply the initial strength gate so the button is properly
        // disabled until the user types a strong phrase.
        refreshPasswordStrength();
      })
      .catch(function (err) {
        setStatus(
          "vault-load-status",
          "Crypto module init error: " + (err && err.message ? err.message : err),
          "err"
        );
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
