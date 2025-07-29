// SPDX-License-Identifier: GNU General Public License v3.0
pragma solidity ^0.8.30;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title DelegationSponsorEIP7702
///        Anyone can sponsor gas for their users, as authorized by EIP7702
/// @author Nidz (nidz-the-fact)
/// @notice Implements EIP-7702 pattern where user signs and sponsor pays gas
/// @dev Requires sponsor to call execute/executeBatch. Each call must be authorized by user (signature) every time, with unique nonce per call.
contract DelegationSponsorEIP7702 is ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    mapping(address => mapping(uint256 => bool)) private nonceUsed;
    mapping(bytes => bool) private signatureUsed;
    mapping(bytes32 => bool) private proofUsed;

    struct Call {
        bytes data;
        address to;
        uint256 value;
    }

    event CallExecuted(
        address indexed sponsor,
        address indexed eoa,
        bytes data,
        address to,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    );

    event BatchExecuted(
        address indexed sponsor,
        address indexed eoa,
        bytes[] data,
        address[] to,
        uint256[] value,
        uint256 nonce,
        uint256 deadline
    );

    error InvalidSigner();
    error NonceAlreadyUsed();
    error ProofAlreadyUsed();
    error ExternalCallFailed();
    error SignatureAlreadyUsed();

    // @notice Execute one sponsored call, signed by contract itself (EOA to SCA)
    function execute(
        address sponsor,
        address user,
        Call calldata call,
        uint256 nonce,
        bytes memory signature,
        uint256 deadline
    ) external payable nonReentrant {
        require(sponsor == msg.sender, "Sponsor must call");
        require(user == address(this), "Not Authorized");
        require(deadline >= block.timestamp, "Deadline exceeded");
        
        bytes32 proof = keccak256(
            abi.encodePacked(
                block.chainid,
                sponsor,
                user,
                nonce,
                deadline
            )
        );

        if (proofUsed[proof]) revert ProofAlreadyUsed();
        proofUsed[proof] = true;
        if (nonceUsed[user][nonce]) revert NonceAlreadyUsed();
        nonceUsed[user][nonce] = true;
        if (signatureUsed[signature]) revert SignatureAlreadyUsed();
        signatureUsed[signature] = true;

        address recovered = proof.toEthSignedMessageHash().recover(signature);
        if (recovered != address(this)) revert InvalidSigner();

        (bool success,) = call.to.call{value: call.value}(call.data);
        if (!success) revert ExternalCallFailed();

        emit CallExecuted(
            sponsor,
            user,
            call.data,
            call.to, 
            call.value,
            nonce,
            deadline
        );
    }

    // @notice Execute multiple sponsored calls in batch with single signature
    function executeBatch(
        address sponsor, 
        address user, 
        Call[] calldata calls,
        uint256 nonce, 
        bytes memory signature, 
        uint256 deadline
    ) external payable nonReentrant {
        require(sponsor == msg.sender, "Sponsor must call");
        require(user == address(this), "Not Authorized");
        require(deadline >= block.timestamp, "Deadline exceeded");

        bytes32 proof = keccak256(
            abi.encodePacked(
                block.chainid,
                sponsor,
                user,
                nonce,
                deadline
            )
        );

        if (proofUsed[proof]) revert ProofAlreadyUsed();
        proofUsed[proof] = true;
        if (nonceUsed[user][nonce]) revert NonceAlreadyUsed();
        nonceUsed[user][nonce] = true;
        if (signatureUsed[signature]) revert SignatureAlreadyUsed();
        signatureUsed[signature] = true;
        
        address recovered = proof.toEthSignedMessageHash().recover(signature);
        if (recovered != address(this)) revert InvalidSigner();

        bytes[] memory data = new bytes[](calls.length);
        address[] memory to = new address[](calls.length);
        uint256[] memory value = new uint256[](calls.length);

        for (uint256 i = 0; i < calls.length; i++) {
            (bool success,) = calls[i].to.call{value: calls[i].value}(calls[i].data);
            if (!success) revert ExternalCallFailed();

            data[i] = calls[i].data;
            to[i] = calls[i].to;
            value[i] = calls[i].value;
        }

        emit BatchExecuted(
            sponsor,
            user,
            data,
            to,
            value,
            nonce,
            deadline
        );
    }

    // @notice Allow receive ETH and fallback
    receive() external payable {}
    fallback() external payable {}
}
