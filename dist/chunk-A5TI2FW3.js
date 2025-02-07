// ../../node_modules/@aws-sdk/core/dist-es/submodules/client/setCredentialFeature.js
function setCredentialFeature(credentials, feature, value) {
  if (!credentials.$source) {
    credentials.$source = {};
  }
  credentials.$source[feature] = value;
  return credentials;
}

export {
  setCredentialFeature
};
//# sourceMappingURL=chunk-A5TI2FW3.js.map