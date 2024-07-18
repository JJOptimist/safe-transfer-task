// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract SafeExchange {
    using EnumerableSet for EnumerableSet.AddressSet;

    address public owner;
    EnumerableSet.AddressSet private authorizedAddresses;

    event CoinsReceived(address indexed from, uint256 amount);
    event CoinsSent(address indexed to, uint256 amount);
    event AddressAdded(address indexed authorizedAddress);
    event AddressRemoved(address indexed authorizedAddress);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedAddresses.contains(msg.sender), "Address is not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {
        emit CoinsReceived(msg.sender, msg.value);
    }

    function addAddress(address _address) external onlyOwner {
        require(!authorizedAddresses.contains(_address), "Address already authorized");
        authorizedAddresses.add(_address);
        emit AddressAdded(_address);
    }

    function removeAddress(address _address) external onlyOwner {
        require(authorizedAddresses.contains(_address), "Address not authorized");
        authorizedAddresses.remove(_address);
        emit AddressRemoved(_address);
    }

    function sendCoins(address payable _to, uint256 _amount, bytes memory _signature) external onlyAuthorized {
        bytes32 message = keccak256(abi.encodePacked(_to, _amount, address(this)));
        bytes32 prefixedMessage = prefixed(message);
        
        require(SignatureChecker.isValidSignatureNow(owner, prefixedMessage, _signature), "Invalid signature");
        
        require(address(this).balance >= _amount, "Insufficient balance");
        _to.transfer(_amount);
        emit CoinsSent(_to, _amount);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function getAddresses() external view returns (address[] memory) {
        return authorizedAddresses.values();
    }
}
