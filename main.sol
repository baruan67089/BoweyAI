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
