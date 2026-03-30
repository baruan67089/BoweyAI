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
