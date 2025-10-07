const CertificateVerifier = artifacts.require("CertificateVerifier");

module.exports = function(deployer) {
  deployer.deploy(CertificateVerifier);
};