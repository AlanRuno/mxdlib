// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract BNBToMXDBridge is ReentrancyGuard, Ownable, Pausable {
    using SafeERC20 for IERC20;

    // ---- Configurable params (constructor + setters) ----
    IERC20 public immutable mxdToken;

    // Per-tx and per-user cap (optional; keep your original behavior)
    uint256 public maxSingleTransfer = 10_000 * 1e18;       // 10,000 MXD
    uint256 public userDailyLimit   = 100_000 * 1e18;       // 100,000 MXD/user/day

    // NEW: Global cap (matches your announcement)
    uint256 public globalDailyLimit = 100_000 * 1e18;       // 100,000 MXD/contract/day

    // ---- Accounting ----
    mapping(address => uint256) public userDailyTransferred;
    mapping(address => uint256) public userLastDay;
    mapping(bytes32 => bool)    public processedTransfers;

    // NEW: global day bucket
    uint256 public globalDailyTransferred;
    uint256 public lastGlobalDay;

    // NEW: deterministic nonces (cleaner transferIds)
    mapping(address => uint256) public nonces;

    // ---- Events ----
    event BridgeTransfer(
        address indexed sender,
        string mxdRecipient,
        bytes32 indexed recipientHash, // keccak256(bytes(mxdRecipient)) for indexing
        uint256 amount,
        bytes32 indexed transferId,
        uint256 timestamp
    );

    event BridgeProcessed(bytes32 indexed transferId, bool success);
    event LimitsUpdated(uint256 maxSingle, uint256 userDaily, uint256 globalDaily);
    event Paused();
    event Unpaused();

    constructor(address _mxdToken, address initialOwner) Ownable(initialOwner) {
        require(_mxdToken != address(0), "mxd token required");
        mxdToken = IERC20(_mxdToken);
    }

    // ---- Core ----
    modifier validMXDAddress(string memory mxdRecipient) {
        require(bytes(mxdRecipient).length > 0, "Invalid MXD recipient");
        _;
    }

    function bridgeToMXD(string memory mxdRecipient, uint256 amount)
        external
        nonReentrant
        whenNotPaused
        validMXDAddress(mxdRecipient)
    {
        require(amount > 0, "Amount must be > 0");
        require(amount <= maxSingleTransfer, "Exceeds per-tx limit");

        // Day bucket rollover
        uint256 day = block.timestamp / 86400;
        if (userLastDay[msg.sender] < day) {
            userDailyTransferred[msg.sender] = 0;
            userLastDay[msg.sender] = day;
        }
        if (lastGlobalDay < day) {
            globalDailyTransferred = 0;
            lastGlobalDay = day;
        }

        // Enforce per-user + global caps
        require(
            userDailyTransferred[msg.sender] + amount <= userDailyLimit,
            "User daily limit exceeded"
        );
        require(
            globalDailyTransferred + amount <= globalDailyLimit,
            "Global daily limit exceeded"
        );

        // Effects
        userDailyTransferred[msg.sender] += amount;
        globalDailyTransferred += amount;

        // Pull tokens
        mxdToken.safeTransferFrom(msg.sender, address(this), amount);

        // Deterministic transferId
        uint256 nonce = nonces[msg.sender]++;
        bytes32 transferId = keccak256(
            abi.encodePacked(address(this), msg.sender, nonce, amount, mxdRecipient)
        );

        emit BridgeTransfer(
            msg.sender,
            mxdRecipient,
            keccak256(bytes(mxdRecipient)),
            amount,
            transferId,
            block.timestamp
        );
    }

    function markTransferProcessed(bytes32 transferId) external onlyOwner {
        require(!processedTransfers[transferId], "Already processed");
        processedTransfers[transferId] = true;
        emit BridgeProcessed(transferId, true);
    }

    // ---- Admin ----
    function setLimits(
        uint256 _maxSingle,
        uint256 _userDaily,
        uint256 _globalDaily
    ) external onlyOwner {
        require(_maxSingle > 0 && _userDaily >= _maxSingle && _globalDaily >= _maxSingle, "Bad limits");
        maxSingleTransfer = _maxSingle;
        userDailyLimit = _userDaily;
        globalDailyLimit = _globalDaily;
        emit LimitsUpdated(_maxSingle, _userDaily, _globalDaily);
    }

    function pause() external onlyOwner { _pause(); emit Paused(); }
    function unpause() external onlyOwner { _unpause(); emit Unpaused(); }

    // Recover MXD (or any mistakenly-sent ERC20) to owner
    function recoverERC20(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(owner(), amount);
    }

    // ---- Views ----
    function getUserDailyInfo(address user)
        external
        view
        returns (uint256 transferred, uint256 remaining, uint256 resetTime)
    {
        uint256 day = block.timestamp / 86400;
        transferred = (userLastDay[user] < day) ? 0 : userDailyTransferred[user];
        remaining = (userDailyLimit > transferred) ? (userDailyLimit - transferred) : 0;
        resetTime = (day + 1) * 86400;
    }

    function getGlobalDailyInfo()
        external
        view
        returns (uint256 transferred, uint256 remaining, uint256 resetTime)
    {
        uint256 day = block.timestamp / 86400;
        transferred = (lastGlobalDay < day) ? 0 : globalDailyTransferred;
        remaining = (globalDailyLimit > transferred) ? (globalDailyLimit - transferred) : 0;
        resetTime = (day + 1) * 86400;
    }
}
