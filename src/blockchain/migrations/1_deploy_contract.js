const BHICSLog = artifacts.require("BHICSLog");

module.exports = function(deployer) {
  deployer.deploy(BHICSLog);
};