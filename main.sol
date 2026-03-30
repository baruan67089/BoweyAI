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
