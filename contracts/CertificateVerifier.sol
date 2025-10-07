// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateVerifier {
    address public owner;
    
    // Maps hash of (studentId + certificateData) to certificate metadata
    mapping(bytes32 => CertificateInfo) public certificates;
    
    struct CertificateInfo {
        string ipfsHash;      // IPFS hash of the full certificate
        uint256 issueDate;    // Timestamp when certificate was issued
        address issuer;       // Address of the institution that issued the certificate
        bool isRevoked;       // Certificate revocation status
    }
    
    // Events for logging
    event CertificateIssued(bytes32 indexed certificateHash, string ipfsHash, address issuer);
    event CertificateRevoked(bytes32 indexed certificateHash);
    
    // Authorized institutions that can issue certificates
    mapping(address => bool) public authorizedIssuers;
    
    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    modifier onlyAuthorized() {
        require(authorizedIssuers[msg.sender], "Not authorized to issue certificates");
        _;
    }
    
    // Add or remove authorized issuers
    function setIssuerStatus(address issuer, bool status) external onlyOwner {
        authorizedIssuers[issuer] = status;
    }
    
    // Issue a new certificate
    function issueCertificate(bytes32 certificateHash, string memory ipfsHash) external onlyAuthorized {
        require(certificates[certificateHash].issueDate == 0, "Certificate already exists");
        
        certificates[certificateHash] = CertificateInfo({
            ipfsHash: ipfsHash,
            issueDate: block.timestamp,
            issuer: msg.sender,
            isRevoked: false
        });
        
        emit CertificateIssued(certificateHash, ipfsHash, msg.sender);
    }
    
    // Revoke a certificate if needed
    function revokeCertificate(bytes32 certificateHash) external onlyAuthorized {
        require(certificates[certificateHash].issueDate > 0, "Certificate does not exist");
        require(!certificates[certificateHash].isRevoked, "Certificate already revoked");
        
        certificates[certificateHash].isRevoked = true;
        emit CertificateRevoked(certificateHash);
    }
    
    // Verify a certificate (public method, no gas cost if called externally)
    function verifyCertificate(bytes32 certificateHash) external view returns (
        bool exists,
        bool isValid,
        string memory ipfsHash,
        uint256 issueDate,
        address issuer
    ) {
        CertificateInfo memory cert = certificates[certificateHash];
        
        exists = cert.issueDate > 0;
        isValid = exists && !cert.isRevoked;
        
        return (
            exists,
            isValid,
            cert.ipfsHash,
            cert.issueDate,
            cert.issuer
        );
    }
}