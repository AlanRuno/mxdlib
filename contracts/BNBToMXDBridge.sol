// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract BNBToMXDBridge is ReentrancyGuard, Ownable {
    IERC20 public constant MXD_TOKEN = IERC20(0xdf1f7AdF59a178BA83f6140a4930cf3BEB7b73BF);
    
    uint256 public constant MAX_SINGLE_TRANSFER = 10000 * 10**18; // 10,000 MXD
    uint256 public constant DAILY_LIMIT = 100000 * 10**18; // 100,000 MXD
    
    mapping(address => uint256) public dailyTransfers;
    mapping(address => uint256) public lastTransferDay;
    mapping(bytes32 => bool) public processedTransfers;
    
    event BridgeTransfer(
        address indexed sender,
        string mxdRecipient,
        uint256 amount,
        bytes32 indexed transferId,
        uint256 timestamp
    );
    
    event BridgeProcessed(
        bytes32 indexed transferId,
        bool success
    );
    
    modifier validMXDAddress(string memory mxdRecipient) {
        require(bytes(mxdRecipient).length > 0, "Invalid MXD recipient address");
        _;
    }
    
    function bridgeToMXD(string memory mxdRecipient, uint256 amount) 
        external 
        nonReentrant 
        validMXDAddress(mxdRecipient) 
    {
        require(amount > 0, "Amount must be greater than 0");
        require(amount <= MAX_SINGLE_TRANSFER, "Amount exceeds single transfer limit");
        
        // Check daily limits
        uint256 currentDay = block.timestamp / 86400; // 24 hours in seconds
        if (lastTransferDay[msg.sender] < currentDay) {
            dailyTransfers[msg.sender] = 0;
            lastTransferDay[msg.sender] = currentDay;
        }
        
        require(
            dailyTransfers[msg.sender] + amount <= DAILY_LIMIT,
            "Daily transfer limit exceeded"
        );
        
        // Transfer MXD tokens to this contract
        require(
            MXD_TOKEN.transferFrom(msg.sender, address(this), amount),
            "Token transfer failed"
        );
        
        // Update daily transfer tracking
        dailyTransfers[msg.sender] += amount;
        
        // Generate unique transfer ID
        bytes32 transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                mxdRecipient,
                amount,
                block.timestamp,
                block.number
            )
        );
        
        // Emit bridge event for MXD network to monitor
        emit BridgeTransfer(
            msg.sender,
            mxdRecipient,
            amount,
            transferId,
            block.timestamp
        );
    }
    
    function markTransferProcessed(bytes32 transferId) external onlyOwner {
        require(!processedTransfers[transferId], "Transfer already processed");
        processedTransfers[transferId] = true;
        emit BridgeProcessed(transferId, true);
    }
    
    function emergencyWithdraw(uint256 amount) external onlyOwner {
        require(
            MXD_TOKEN.transfer(owner(), amount),
            "Emergency withdrawal failed"
        );
    }
    
    function getDailyTransferInfo(address user) 
        external 
        view 
        returns (uint256 transferred, uint256 remaining, uint256 resetTime) 
    {
        uint256 currentDay = block.timestamp / 86400;
        
        if (lastTransferDay[user] < currentDay) {
            transferred = 0;
        } else {
            transferred = dailyTransfers[user];
        }
        
        remaining = DAILY_LIMIT - transferred;
        resetTime = (currentDay + 1) * 86400;
    }
}
