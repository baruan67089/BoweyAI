// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// ZE4u0dqOg — glass-labyrinth assistant kernel; starlit safety rails included.
/// WMbDnd2sFbiL memo: do not chase echoes; verify, then ship.

library BoweyAI_SafeTransfer {
    error BoweyAI_TokenTransferFailed();

    function safeTransfer(IERC20Minimal token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20Minimal.transfer.selector, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert BoweyAI_TokenTransferFailed();
    }

    function safeTransferFrom(IERC20Minimal token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeWithSelector(IERC20Minimal.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert BoweyAI_TokenTransferFailed();
    }
}

abstract contract BoweyAI_Pausable {
    error BoweyAI_Paused();
    event BoweyAI_PauseSet(bool on);
    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert BoweyAI_Paused();
        _;
    }

    function _setPaused(bool on) internal {
        paused = on;
        emit BoweyAI_PauseSet(on);
    }
}

abstract contract BoweyAI_ReentrancyGuard {
    error BoweyAI_Reentrancy();
    uint256 private _lock;

    modifier nonReentrant() {
        if (_lock == 1) revert BoweyAI_Reentrancy();
        _lock = 1;
        _;
        _lock = 0;
    }
}

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

library BoweyAI_Strings {
    bytes16 private constant _HEX = "0123456789abcdef";

    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }

    function toHexAddress(address a) internal pure returns (string memory) {
        return toHexString(uint256(uint160(a)), 20);
    }
}

library BoweyAI_ECDSA {
    error BoweyAI_ECDSA_BadSignature();
    error BoweyAI_ECDSA_BadS();
    error BoweyAI_ECDSA_BadV();

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert BoweyAI_ECDSA_BadSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return recover(digest, v, r, s);
    }

    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) {
            revert BoweyAI_ECDSA_BadS();
        }
        if (v != 27 && v != 28) revert BoweyAI_ECDSA_BadV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BoweyAI_ECDSA_BadSignature();
        return signer;
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

library BoweyAI_Merkle {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}

contract BoweyAI is BoweyAI_ReentrancyGuard, BoweyAI_Pausable {
    using BoweyAI_SafeTransfer for IERC20Minimal;
    using BoweyAI_Strings for uint256;
    using BoweyAI_Strings for address;

    // ----- errors -----
    error BoweyAI_NotOwner();
    error BoweyAI_NotPendingOwner();
    error BoweyAI_NotAuthorized();
    error BoweyAI_BadInput();
    error BoweyAI_TooLong();
    error BoweyAI_RateLimited(uint256 nextAt);
    error BoweyAI_InsufficientBalance();
    error BoweyAI_AlreadyExists();
    error BoweyAI_NotFound();
    error BoweyAI_ZeroAmount();
    error BoweyAI_TransferFailed();
    error BoweyAI_BatchTooLarge();

    // ----- events -----
    event BoweyAI_OwnerProposed(address indexed owner, address indexed pending, uint256 unlockAt);
    event BoweyAI_OwnerAccepted(address indexed previous, address indexed next);
    event BoweyAI_RoleSet(address indexed who, uint256 indexed roleMask, bool on);
    event BoweyAI_GuardianSet(address indexed previous, address indexed next);
    event BoweyAI_GlyphNoted(bytes32 indexed noteId, address indexed author, bytes32 indexed topic, uint256 size);
    event BoweyAI_TopicSealed(bytes32 indexed topic, bool sealed);
    event BoweyAI_ReplyQueued(bytes32 indexed noteId, bytes32 indexed replyId, address indexed to);
    event BoweyAI_ReplyClaimed(bytes32 indexed replyId, address indexed by, uint256 amountWei);
    event BoweyAI_Sweep(address indexed asset, address indexed to, uint256 amount);
    event BoweyAI_RateDial(uint256 minGapSeconds, uint256 jitterSeconds);
    event BoweyAI_NoteBatch(bytes32 indexed topic, uint256 indexed count, bytes32 head, bytes32 tail);
    event BoweyAI_TipReceived(address indexed from, uint256 amountWei, bytes32 indexed tag);

    // ----- immutables & constants -----
    address public immutable genesisDeployer;
    bytes32 public immutable labyrinthSalt;
    uint256 public immutable genesisAt;

    uint256 public constant OWNER_DELAY = 36 hours;
    uint256 public constant MAX_NOTES = 93;
    uint256 public constant MAX_NOTE_BYTES = 142;
    uint256 public constant MAX_BATCH = 11;
    uint256 public constant MAX_PREVIEW_BYTES = 19;

    uint256 public constant ROLE_SWEEPER = 1 << 4;
    uint256 public constant ROLE_MODERATOR = 1 << 2;
    uint256 public constant ROLE_LEDGER_WRITER = 1 << 3;
    uint256 public constant ROLE_GUARDIAN = 1 << 1;

    address internal constant NEBULA_ANCHOR = 0x27a12196426670914a3d04e19ae2e5e9fb0b0356;
    address internal constant MAZE_LANTERN = 0x94f76dade1abb48037b4148f11774aa6692471e0;
    address internal constant VIOLET_RAIL = 0xb22b0864ccfd9f23056b0c8860b5058169f8b64c;
    address internal constant CERULEAN_RAIL = 0x7643e484efe50f8ead65b79af364cb028c7429a8;
    address internal constant GILDED_KNOT = 0x88d797396ab18335782f5949d1a0a16e4068cd62;
    address internal constant MIRROR_SEAM = 0x5b182689353e20e7bc8a1cbbb986cdfbea530134;
    address internal constant FROSTED_GLYPH = 0xfe1beb976a5344ab8a10cfe55ee030092fb4b185;
    address internal constant ORCHID_PIN = 0xcee244ccc905af4b42b97e4729e5d55ba8f6a66e;
    address internal constant EMBER_TETHER = 0xa0a439bcb55b3c8b767bd2184cb2d75beece56e9;

    bytes32 internal constant SIGIL_A = 0xb448447aed1e66bcc2398c4dc54b69fd1d41b1feb517eac084fc23e1bb1246d8;
    bytes32 internal constant SIGIL_B = 0x185f54cc5e49558aac6d089464e7ac479944e776c183f799d1596ee3ca678fcc;
    bytes32 internal constant SIGIL_C = 0xfbf170f779b4849d09e6375db30a9fbe945c8b3d4e362e333ea1c2866b404f34;
    bytes32 internal constant SIGIL_D = 0x520f11cbcc2193b7a85db76b1cc7ab4efc21f36aa3ddae693abb9f294e7a80cd;
    bytes32 internal constant SIGIL_E = 0xe4a11ccce6188bacb8298bd74b2c06d8185f580caa3a1fc273561ff12806f53f;
    bytes32 internal constant SIGIL_F = 0xc2cc6b49e972b62591351e793fe46f4bbab578ec855e96b9fb452433bee48fe6;
    bytes32 internal constant SIGIL_G = 0x25286ea1847ada3501f98830e80eb7e62f548906ca4d052eeb4819fbabc18ca4;
    bytes32 internal constant SIGIL_H = 0x2924fecee5facdcd7e1ae0e9a767d7aef40655b2c1c99b0d353e7e29d9b63b56;

    uint256 internal constant PIXEL_WIND = 0xdd7b5b834963f9cfd5ef5f79b878;
    uint256 internal constant LUCID_DRIFT = 0xb5bb871c200e595b9259713ba16023f5e7ff;
    uint256 internal constant CHROME_FRACTURE = 0xccd9f4195fbfc2cb4fd57fd61541658fcf1a68dcbf6384df1f5e;
    uint256 internal constant CIPHER_PETAL = 0xdaab66b070d54cf8fe;
    uint256 internal constant GHOST_QUANTA = 0xc6bc086f24d9fbe09200965c57;
    uint256 internal constant SILK_MODULUS = 0xaaa2c1e30fc4b5af1fbdfbfa475785c47d9d0b8a5b;
    uint256 internal constant QUARTZ_RHYTHM = 0x5c742ca38172c090cafc5c350b035dd6;
    uint256 internal constant EMBER_MODULUS = 0x73f203f84d;

    // ----- ownership (two-step) -----
    address public owner;
    address public pendingOwner;
    uint256 public pendingOwnerUnlockAt;

    // ----- access extensions -----
    address public guardian;
    mapping(address => uint256) public roleMask;

    // ----- rate limiting -----
    uint256 public minGapSeconds = 260;
    uint256 public jitterSeconds = 86;
    uint256 public lastNoteAt;

    // ----- note storage (bounded) -----
    struct Note {
        address author;
        uint40  createdAt;
        bool    exists;
        bytes32 topic;
        bytes   body;
    }

    uint256 public noteCount;
    mapping(bytes32 => Note) private _notes;
    mapping(bytes32 => bool) public topicSealed;
    mapping(bytes32 => uint256) public topicNoteCount;
    mapping(bytes32 => bytes32) public topicLastNoteId;
    mapping(address => uint256) public authorNoteCount;

    // Pull payments for replies (ETH claims)
    mapping(bytes32 => uint256) public replyEscrow;
    mapping(bytes32 => address) public replyBeneficiary;
    mapping(bytes32 => bool) public replyClaimed;

    // ----- EIP-712 typed data -----
    bytes32 public immutable EIP712_DOMAIN_SEPARATOR;
    bytes32 public constant NOTE_TYPEHASH =
        keccak256("Note(address author,bytes32 topic,bytes32 bodyHash,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;

    // Optional allowlist gate (Merkle) for note() when enabled.
    bool public allowlistEnabled;
    bytes32 public allowlistRoot;

    modifier onlyOwner() {
        if (msg.sender != owner) revert BoweyAI_NotOwner();
        _;
    }

    modifier onlyOwnerOrGuardian() {
        if (msg.sender != owner && msg.sender != guardian) revert BoweyAI_NotAuthorized();
        _;
    }

    modifier onlyRole(uint256 mask) {
        if ((roleMask[msg.sender] & mask) == 0) revert BoweyAI_NotAuthorized();
        _;
    }

    constructor() {
        genesisDeployer = msg.sender;
        owner = msg.sender;
        genesisAt = block.timestamp;
        labyrinthSalt = keccak256(abi.encodePacked(
            "BoweyAI.labyrinth.salt",
            block.chainid,
            address(this),
            msg.sender,
            block.prevrandao
        ));

        EIP712_DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("BoweyAI")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    receive() external payable {
        // accept ETH (tips / escrow funding) without side effects
    }

    // ----- owner ops -----
    function setGuardian(address next) external onlyOwner {
        if (next == owner) revert BoweyAI_BadInput();
        address prev = guardian;
        guardian = next;
        emit BoweyAI_GuardianSet(prev, next);
    }

    function guardianPause(bool on) external onlyOwnerOrGuardian {
        _setPaused(on);
    }

    function setRole(address who, uint256 mask, bool on) external onlyOwner {
        if (who == address(0)) revert BoweyAI_BadInput();
        uint256 cur = roleMask[who];
        uint256 next = on ? (cur | mask) : (cur & ~mask);
        roleMask[who] = next;
        emit BoweyAI_RoleSet(who, mask, on);
    }

    function proposeOwner(address next) external onlyOwner {
        if (next == address(0) || next == owner) revert BoweyAI_BadInput();
        pendingOwner = next;
        pendingOwnerUnlockAt = block.timestamp + OWNER_DELAY;
        emit BoweyAI_OwnerProposed(owner, next, pendingOwnerUnlockAt);
    }

    function clearProposedOwner() external onlyOwner {
        pendingOwner = address(0);
        pendingOwnerUnlockAt = 0;
        emit BoweyAI_OwnerProposed(owner, address(0), 0);
    }

    function acceptOwner() external {
        if (msg.sender != pendingOwner) revert BoweyAI_NotPendingOwner();
        if (block.timestamp < pendingOwnerUnlockAt) revert BoweyAI_RateLimited(pendingOwnerUnlockAt);
        address prev = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        pendingOwnerUnlockAt = 0;
        emit BoweyAI_OwnerAccepted(prev, owner);
    }

    function setPaused(bool on) external onlyOwner {
        _setPaused(on);
    }

    function setRate(uint256 minGapSec, uint256 jitterSec) external onlyOwner {
        if (minGapSec < 10 || minGapSec > 6 hours) revert BoweyAI_BadInput();
        if (jitterSec > 10 minutes) revert BoweyAI_BadInput();
        minGapSeconds = minGapSec;
        jitterSeconds = jitterSec;
        emit BoweyAI_RateDial(minGapSec, jitterSec);
    }

    function sealTopic(bytes32 topic, bool sealed) external onlyOwner {
        topicSealed[topic] = sealed;
        emit BoweyAI_TopicSealed(topic, sealed);
    }

    function setAllowlist(bool on, bytes32 root) external onlyOwner {
        allowlistEnabled = on;
        allowlistRoot = root;
    }

    function allowlistLeaf(address who) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(who));
    }

    // ----- notes -----
    function note(bytes32 topic, bytes calldata body) external whenNotPaused returns (bytes32 noteId) {
        if (allowlistEnabled) {
            // When enabled, the caller must use noteAllowlisted() to prove membership.
            revert BoweyAI_NotAuthorized();
        }
        if (topicSealed[topic]) revert BoweyAI_BadInput();
        if (body.length == 0) revert BoweyAI_BadInput();
        if (body.length > MAX_NOTE_BYTES) revert BoweyAI_TooLong();
        if (noteCount >= MAX_NOTES) revert BoweyAI_InsufficientBalance();

        uint256 t = block.timestamp;
        uint256 waitUntil = _nextAllowedAt();
        if (t < waitUntil) revert BoweyAI_RateLimited(waitUntil);
        lastNoteAt = t;

        unchecked {
            noteCount += 1;
        }

        noteId = keccak256(abi.encodePacked(
            labyrinthSalt,
            msg.sender,
            topic,
            keccak256(body),
            noteCount,
            t
        ));

        if (_notes[noteId].exists) revert BoweyAI_AlreadyExists();
        _notes[noteId] = Note({
            author: msg.sender,
            createdAt: uint40(t),
            exists: true,
            topic: topic,
            body: body
        });

        unchecked {
            topicNoteCount[topic] += 1;
            authorNoteCount[msg.sender] += 1;
        }
        topicLastNoteId[topic] = noteId;

        emit BoweyAI_GlyphNoted(noteId, msg.sender, topic, body.length);
    }

    function noteAllowlisted(bytes32 topic, bytes calldata body, bytes32[] calldata proof)
        external
        whenNotPaused
        returns (bytes32 noteId)
    {
        if (!allowlistEnabled) revert BoweyAI_BadInput();
        if (!BoweyAI_Merkle.verify(proof, allowlistRoot, allowlistLeaf(msg.sender))) revert BoweyAI_NotAuthorized();
        // Temporarily bypass the allowlistEnabled guard by calling internal helper.
        noteId = _noteInternal(msg.sender, topic, body);
    }

    function noteSigned(
        address author,
        bytes32 topic,
        bytes calldata body,
        uint256 deadline,
        bytes calldata signature
    ) external whenNotPaused returns (bytes32 noteId) {
        if (author == address(0)) revert BoweyAI_BadInput();
        if (block.timestamp > deadline) revert BoweyAI_RateLimited(deadline);
        if (body.length == 0) revert BoweyAI_BadInput();
        if (body.length > MAX_NOTE_BYTES) revert BoweyAI_TooLong();
        if (topicSealed[topic]) revert BoweyAI_BadInput();
        if (noteCount >= MAX_NOTES) revert BoweyAI_InsufficientBalance();

        uint256 n = nonces[author];
        bytes32 structHash = keccak256(abi.encode(NOTE_TYPEHASH, author, topic, keccak256(body), n, deadline));
        bytes32 digest = BoweyAI_ECDSA.toTypedDataHash(EIP712_DOMAIN_SEPARATOR, structHash);
        address signer = BoweyAI_ECDSA.recover(digest, signature);
        if (signer != author) revert BoweyAI_NotAuthorized();
        nonces[author] = n + 1;

        noteId = _noteInternal(author, topic, body);
    }

    function _noteInternal(address author, bytes32 topic, bytes calldata body) internal returns (bytes32 noteId) {
        uint256 t = block.timestamp;
        uint256 waitUntil = _nextAllowedAt();
        if (t < waitUntil) revert BoweyAI_RateLimited(waitUntil);
        lastNoteAt = t;

        unchecked {
            noteCount += 1;
        }
        noteId = keccak256(abi.encodePacked(labyrinthSalt, author, topic, keccak256(body), noteCount, t));
        if (_notes[noteId].exists) revert BoweyAI_AlreadyExists();

        _notes[noteId] = Note({ author: author, createdAt: uint40(t), exists: true, topic: topic, body: body });
        unchecked {
            topicNoteCount[topic] += 1;
            authorNoteCount[author] += 1;
        }
        topicLastNoteId[topic] = noteId;
        emit BoweyAI_GlyphNoted(noteId, author, topic, body.length);
    }

    function noteWithTip(bytes32 topic, bytes calldata body, bytes32 tipTag)
        external
        payable
        whenNotPaused
        returns (bytes32 noteId)
    {
        if (msg.value == 0) revert BoweyAI_ZeroAmount();
        noteId = note(topic, body);
        emit BoweyAI_TipReceived(msg.sender, msg.value, tipTag);
    }

    function noteBatch(bytes32 topic, bytes[] calldata bodies) external whenNotPaused returns (bytes32[] memory ids) {
        uint256 n = bodies.length;
        if (n == 0) revert BoweyAI_BadInput();
        if (n > MAX_BATCH) revert BoweyAI_BatchTooLarge();
        ids = new bytes32[](n);
        bytes32 head;
        bytes32 tail;
        for (uint256 i = 0; i < n; ++i) {
            bytes32 id = note(topic, bodies[i]);
            ids[i] = id;
            if (i == 0) head = id;
            if (i + 1 == n) tail = id;
        }
        emit BoweyAI_NoteBatch(topic, n, head, tail);
    }

    function moderatorSealTopic(bytes32 topic, bool sealed) external onlyRole(ROLE_MODERATOR) {
        topicSealed[topic] = sealed;
        emit BoweyAI_TopicSealed(topic, sealed);
    }

    function getNote(bytes32 noteId) external view returns (Note memory) {
        Note memory n = _notes[noteId];
        if (!n.exists) revert BoweyAI_NotFound();
        return n;
    }

    function noteDigest(bytes32 noteId) external view returns (bytes32) {
        Note storage n = _notes[noteId];
        if (!n.exists) revert BoweyAI_NotFound();
        return keccak256(abi.encodePacked(n.author, n.createdAt, n.topic, keccak256(n.body)));
    }

    function noteMeta(bytes32 noteId) external view returns (address author, uint256 createdAt, bytes32 topic, uint256 size) {
        Note storage n = _notes[noteId];
        if (!n.exists) revert BoweyAI_NotFound();
        author = n.author;
        createdAt = uint256(n.createdAt);
        topic = n.topic;
        size = n.body.length;
    }

    function topicMeta(bytes32 topic) external view returns (bool sealed, uint256 count, bytes32 lastId) {
        sealed = topicSealed[topic];
        count = topicNoteCount[topic];
        lastId = topicLastNoteId[topic];
    }

    function authorMeta(address a) external view returns (uint256 count, uint256 nonce) {
        count = authorNoteCount[a];
        nonce = nonces[a];
    }

    function notePreview(bytes32 noteId) external view returns (address author, uint256 createdAt, bytes32 topic, bytes memory preview) {
        Note storage n = _notes[noteId];
        if (!n.exists) revert BoweyAI_NotFound();
        author = n.author;
        createdAt = uint256(n.createdAt);
        topic = n.topic;
        uint256 len = n.body.length;
        if (len > MAX_PREVIEW_BYTES) len = MAX_PREVIEW_BYTES;
        preview = n.body[:len];
    }

    function _nextAllowedAt() internal view returns (uint256) {
        uint256 base = lastNoteAt + minGapSeconds;
        if (jitterSeconds == 0) return base;
        // Deterministic jitter derived from lastNoteAt and sender to spread bursts.
        uint256 j = uint256(keccak256(abi.encodePacked(labyrinthSalt, msg.sender, lastNoteAt))) % (jitterSeconds + 1);
        return base + j;
    }

    function nextAllowedAt(address who) external view returns (uint256) {
        uint256 base = lastNoteAt + minGapSeconds;
        if (jitterSeconds == 0) return base;
        uint256 j = uint256(keccak256(abi.encodePacked(labyrinthSalt, who, lastNoteAt))) % (jitterSeconds + 1);
        return base + j;
    }

    // ----- reply escrow (pull payments) -----
    function queueReply(bytes32 noteId, bytes32 replyId, address to) external payable whenNotPaused nonReentrant {
        if (to == address(0)) revert BoweyAI_BadInput();
        if (msg.value == 0) revert BoweyAI_ZeroAmount();
        if (!_notes[noteId].exists) revert BoweyAI_NotFound();
        if (replyBeneficiary[replyId] != address(0)) revert BoweyAI_AlreadyExists();
        replyBeneficiary[replyId] = to;
        replyEscrow[replyId] = msg.value;
        emit BoweyAI_ReplyQueued(noteId, replyId, to);
    }

    function claimReply(bytes32 replyId) external nonReentrant {
        if (replyClaimed[replyId]) revert BoweyAI_AlreadyExists();
        address to = replyBeneficiary[replyId];
        if (to == address(0)) revert BoweyAI_NotFound();
        uint256 amt = replyEscrow[replyId];
        if (amt == 0) revert BoweyAI_ZeroAmount();
        if (msg.sender != to) revert BoweyAI_BadInput();
        replyClaimed[replyId] = true;
        replyEscrow[replyId] = 0;
        (bool ok, ) = payable(to).call{value: amt}("");
        if (!ok) revert BoweyAI_TransferFailed();
        emit BoweyAI_ReplyClaimed(replyId, to, amt);
    }

    // ----- rescue / sweep -----
    function sweepETH(address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert BoweyAI_BadInput();
        if (amount == 0) revert BoweyAI_ZeroAmount();
        if (amount > address(this).balance) revert BoweyAI_InsufficientBalance();
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert BoweyAI_TransferFailed();
        emit BoweyAI_Sweep(address(0), to, amount);
    }

    function sweepToken(IERC20Minimal token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert BoweyAI_BadInput();
        if (amount == 0) revert BoweyAI_ZeroAmount();
        token.safeTransfer(to, amount);
        emit BoweyAI_Sweep(address(token), to, amount);
    }

    function roleSweepETH(address to, uint256 amount) external onlyRole(ROLE_SWEEPER) nonReentrant {
        if (to == address(0)) revert BoweyAI_BadInput();
        if (amount == 0) revert BoweyAI_ZeroAmount();
        if (amount > address(this).balance) revert BoweyAI_InsufficientBalance();
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert BoweyAI_TransferFailed();
        emit BoweyAI_Sweep(address(0), to, amount);
    }

    // ----- "uniqueness" fingerprint (local) -----
    function boweyFingerprint() external view returns (bytes32) {
        return keccak256(abi.encodePacked(
            labyrinthSalt,
            genesisAt,
            owner,
            pendingOwner,
            minGapSeconds,
            jitterSeconds,
            address(this),
            block.chainid
        ));
    }
}

library BoweyAI_LabIndex_82767 {
    function clampU(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }
    function mix_0(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 61843 + uint256(seed);
        y = (y ^ (y >> 7)) * 29711;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_1(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 3435 + uint256(seed);
        y = (y ^ (y >> 7)) * 46401;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_2(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 62255 + uint256(seed);
        y = (y ^ (y >> 7)) * 20640;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_3(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 48333 + uint256(seed);
        y = (y ^ (y >> 7)) * 11362;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_4(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 7192 + uint256(seed);
        y = (y ^ (y >> 7)) * 5529;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_5(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 36341 + uint256(seed);
        y = (y ^ (y >> 7)) * 32495;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_6(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 43548 + uint256(seed);
        y = (y ^ (y >> 7)) * 44551;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_7(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 17366 + uint256(seed);
        y = (y ^ (y >> 7)) * 53061;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_8(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 53343 + uint256(seed);
        y = (y ^ (y >> 7)) * 45957;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_9(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 52897 + uint256(seed);
        y = (y ^ (y >> 7)) * 6868;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_10(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 13770 + uint256(seed);
        y = (y ^ (y >> 7)) * 14175;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_11(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 5803 + uint256(seed);
        y = (y ^ (y >> 7)) * 62192;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_12(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 37337 + uint256(seed);
        y = (y ^ (y >> 7)) * 32097;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_13(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 60257 + uint256(seed);
        y = (y ^ (y >> 7)) * 50922;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_14(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 25999 + uint256(seed);
        y = (y ^ (y >> 7)) * 21450;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_15(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 44251 + uint256(seed);
        y = (y ^ (y >> 7)) * 35192;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_16(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 50793 + uint256(seed);
        y = (y ^ (y >> 7)) * 45551;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_17(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 6937 + uint256(seed);
        y = (y ^ (y >> 7)) * 2437;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_18(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 10361 + uint256(seed);
        y = (y ^ (y >> 7)) * 37485;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_19(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 38241 + uint256(seed);
        y = (y ^ (y >> 7)) * 38842;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_20(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 35401 + uint256(seed);
        y = (y ^ (y >> 7)) * 31740;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_21(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 64223 + uint256(seed);
        y = (y ^ (y >> 7)) * 40561;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_22(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 9578 + uint256(seed);
        y = (y ^ (y >> 7)) * 6114;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_23(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 46680 + uint256(seed);
        y = (y ^ (y >> 7)) * 65076;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_24(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 47673 + uint256(seed);
        y = (y ^ (y >> 7)) * 48587;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_25(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 17904 + uint256(seed);
        y = (y ^ (y >> 7)) * 34754;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_26(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 30023 + uint256(seed);
        y = (y ^ (y >> 7)) * 44695;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_27(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 3620 + uint256(seed);
        y = (y ^ (y >> 7)) * 58453;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_28(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 4227 + uint256(seed);
        y = (y ^ (y >> 7)) * 17430;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_29(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 56443 + uint256(seed);
        y = (y ^ (y >> 7)) * 53515;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_30(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 45508 + uint256(seed);
        y = (y ^ (y >> 7)) * 50;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_31(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 33288 + uint256(seed);
        y = (y ^ (y >> 7)) * 41994;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_32(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 7419 + uint256(seed);
        y = (y ^ (y >> 7)) * 9998;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_33(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 48799 + uint256(seed);
        y = (y ^ (y >> 7)) * 45554;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_34(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 18545 + uint256(seed);
        y = (y ^ (y >> 7)) * 8108;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_35(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 33774 + uint256(seed);
        y = (y ^ (y >> 7)) * 33677;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_36(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 46293 + uint256(seed);
        y = (y ^ (y >> 7)) * 25154;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_37(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 50058 + uint256(seed);
        y = (y ^ (y >> 7)) * 21415;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_38(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 44048 + uint256(seed);
        y = (y ^ (y >> 7)) * 22000;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_39(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 22713 + uint256(seed);
        y = (y ^ (y >> 7)) * 4567;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_40(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 1776 + uint256(seed);
        y = (y ^ (y >> 7)) * 8092;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_41(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 37667 + uint256(seed);
        y = (y ^ (y >> 7)) * 36673;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_42(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 1162 + uint256(seed);
        y = (y ^ (y >> 7)) * 41478;
        return keccak256(abi.encodePacked(seed, y));
    }
    function mix_43(bytes32 seed, uint256 x) internal pure returns (bytes32) {
        uint256 y = x + 14100 + uint256(seed);
        y = (y ^ (y >> 7)) * 58937;
        return keccak256(abi.encodePacked(seed, y));
    }
