import {
  loadRestJsonErrorCode,
  parseJsonBody,
  parseJsonErrorBody
} from "./chunk-DPWCMVXW.js";
import {
  AwsSdkSigV4Signer,
  DEFAULT_RETRY_MODE,
  DefaultIdentityProviderConfig,
  EndpointCache,
  Hash,
  NODE_APP_ID_CONFIG_OPTIONS,
  NODE_MAX_ATTEMPT_CONFIG_OPTIONS,
  NODE_REGION_CONFIG_FILE_OPTIONS,
  NODE_REGION_CONFIG_OPTIONS,
  NODE_RETRY_MODE_CONFIG_OPTIONS,
  NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS,
  NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS,
  NoAuthSigner,
  awsEndpointFunctions,
  calculateBodyLength,
  createDefaultUserAgentProvider,
  customEndpointFunctions,
  emitWarningIfUnsupportedVersion,
  getAwsRegionExtensionConfiguration,
  getContentLengthPlugin,
  getEndpointPlugin,
  getHostHeaderPlugin,
  getHttpAuthSchemeEndpointRuleSetPlugin,
  getHttpSigningPlugin,
  getLoggerPlugin,
  getRecursionDetectionPlugin,
  getRetryPlugin,
  getSerdePlugin,
  getSmithyContext,
  getUserAgentPlugin,
  normalizeProvider,
  resolveAwsRegionExtensionConfiguration,
  resolveAwsSdkSigV4Config,
  resolveDefaultsModeConfig,
  resolveEndpoint,
  resolveEndpointConfig,
  resolveHostHeaderConfig,
  resolveRegionConfig,
  resolveRetryConfig,
  resolveUserAgentConfig
} from "./chunk-K5USRMEH.js";
import {
  loadConfig,
  parseUrl
} from "./chunk-5RDIHNZO.js";
import {
  Client,
  Command,
  NoOpLogger,
  NodeHttpHandler,
  SENSITIVE_STRING,
  ServiceException,
  _json,
  createAggregatedClient,
  decorateServiceException,
  emitWarningIfUnsupportedVersion as emitWarningIfUnsupportedVersion2,
  expectInt32,
  expectNonNull,
  expectObject,
  expectString,
  fromBase64,
  fromUtf8,
  getDefaultExtensionConfiguration,
  getHttpHandlerExtensionConfiguration,
  loadConfigsForDefaultMode,
  map,
  requestBuilder,
  resolveDefaultRuntimeConfig,
  resolveHttpHandlerRuntimeConfig,
  streamCollector,
  take,
  toBase64,
  toUtf8,
  withBaseException
} from "./chunk-7OEE4O7I.js";
import "./chunk-EP5PJPG3.js";
import "./chunk-A5TI2FW3.js";
import "./chunk-CHVQKP74.js";
import "./chunk-2LFJGUP7.js";
import "./chunk-PLDDJCW6.js";

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthSchemeProvider.js
var defaultSSOOIDCHttpAuthSchemeParametersProvider = async (config, context, input) => {
  return {
    operation: getSmithyContext(context).operation,
    region: await normalizeProvider(config.region)() || (() => {
      throw new Error("expected `region` to be configured for `aws.auth#sigv4`");
    })()
  };
};
function createAwsAuthSigv4HttpAuthOption(authParameters) {
  return {
    schemeId: "aws.auth#sigv4",
    signingProperties: {
      name: "sso-oauth",
      region: authParameters.region
    },
    propertiesExtractor: (config, context) => ({
      signingProperties: {
        config,
        context
      }
    })
  };
}
function createSmithyApiNoAuthHttpAuthOption(authParameters) {
  return {
    schemeId: "smithy.api#noAuth"
  };
}
var defaultSSOOIDCHttpAuthSchemeProvider = (authParameters) => {
  const options = [];
  switch (authParameters.operation) {
    case "CreateToken": {
      options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
      break;
    }
    default: {
      options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
    }
  }
  return options;
};
var resolveHttpAuthSchemeConfig = (config) => {
  const config_0 = resolveAwsSdkSigV4Config(config);
  return {
    ...config_0
  };
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/EndpointParameters.js
var resolveClientEndpointParameters = (options) => {
  return {
    ...options,
    useDualstackEndpoint: options.useDualstackEndpoint ?? false,
    useFipsEndpoint: options.useFipsEndpoint ?? false,
    defaultSigningName: "sso-oauth"
  };
};
var commonParams = {
  UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
  Endpoint: { type: "builtInParams", name: "endpoint" },
  Region: { type: "builtInParams", name: "region" },
  UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" }
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/package.json
var package_default = {
  name: "@aws-sdk/nested-clients",
  version: "3.734.0",
  description: "Nested clients for AWS SDK packages.",
  main: "./dist-cjs/index.js",
  module: "./dist-es/index.js",
  types: "./dist-types/index.d.ts",
  scripts: {
    build: "yarn lint && concurrently 'yarn:build:cjs' 'yarn:build:es' 'yarn:build:types'",
    "build:cjs": "node ../../scripts/compilation/inline nested-clients",
    "build:es": "tsc -p tsconfig.es.json",
    "build:include:deps": "lerna run --scope $npm_package_name --include-dependencies build",
    "build:types": "tsc -p tsconfig.types.json",
    "build:types:downlevel": "downlevel-dts dist-types dist-types/ts3.4",
    clean: "rimraf ./dist-* && rimraf *.tsbuildinfo",
    lint: "node ../../scripts/validation/submodules-linter.js --pkg nested-clients",
    test: "yarn g:vitest run",
    "test:watch": "yarn g:vitest watch"
  },
  engines: {
    node: ">=18.0.0"
  },
  author: {
    name: "AWS SDK for JavaScript Team",
    url: "https://aws.amazon.com/javascript/"
  },
  license: "Apache-2.0",
  dependencies: {
    "@aws-crypto/sha256-browser": "5.2.0",
    "@aws-crypto/sha256-js": "5.2.0",
    "@aws-sdk/core": "3.734.0",
    "@aws-sdk/middleware-host-header": "3.734.0",
    "@aws-sdk/middleware-logger": "3.734.0",
    "@aws-sdk/middleware-recursion-detection": "3.734.0",
    "@aws-sdk/middleware-user-agent": "3.734.0",
    "@aws-sdk/region-config-resolver": "3.734.0",
    "@aws-sdk/types": "3.734.0",
    "@aws-sdk/util-endpoints": "3.734.0",
    "@aws-sdk/util-user-agent-browser": "3.734.0",
    "@aws-sdk/util-user-agent-node": "3.734.0",
    "@smithy/config-resolver": "^4.0.1",
    "@smithy/core": "^3.1.1",
    "@smithy/fetch-http-handler": "^5.0.1",
    "@smithy/hash-node": "^4.0.1",
    "@smithy/invalid-dependency": "^4.0.1",
    "@smithy/middleware-content-length": "^4.0.1",
    "@smithy/middleware-endpoint": "^4.0.2",
    "@smithy/middleware-retry": "^4.0.3",
    "@smithy/middleware-serde": "^4.0.1",
    "@smithy/middleware-stack": "^4.0.1",
    "@smithy/node-config-provider": "^4.0.1",
    "@smithy/node-http-handler": "^4.0.2",
    "@smithy/protocol-http": "^5.0.1",
    "@smithy/smithy-client": "^4.1.2",
    "@smithy/types": "^4.1.0",
    "@smithy/url-parser": "^4.0.1",
    "@smithy/util-base64": "^4.0.0",
    "@smithy/util-body-length-browser": "^4.0.0",
    "@smithy/util-body-length-node": "^4.0.0",
    "@smithy/util-defaults-mode-browser": "^4.0.3",
    "@smithy/util-defaults-mode-node": "^4.0.3",
    "@smithy/util-endpoints": "^3.0.1",
    "@smithy/util-middleware": "^4.0.1",
    "@smithy/util-retry": "^4.0.1",
    "@smithy/util-utf8": "^4.0.0",
    tslib: "^2.6.2"
  },
  devDependencies: {
    concurrently: "7.0.0",
    "downlevel-dts": "0.10.1",
    rimraf: "3.0.2",
    typescript: "~5.2.2"
  },
  typesVersions: {
    "<4.0": {
      "dist-types/*": [
        "dist-types/ts3.4/*"
      ]
    }
  },
  files: [
    "./sso-oidc.d.ts",
    "./sso-oidc.js",
    "./sts.d.ts",
    "./sts.js",
    "dist-*/**"
  ],
  browser: {
    "./dist-es/submodules/sso-oidc/runtimeConfig": "./dist-es/submodules/sso-oidc/runtimeConfig.browser",
    "./dist-es/submodules/sts/runtimeConfig": "./dist-es/submodules/sts/runtimeConfig.browser"
  },
  "react-native": {},
  homepage: "https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients",
  repository: {
    type: "git",
    url: "https://github.com/aws/aws-sdk-js-v3.git",
    directory: "packages/nested-clients"
  },
  exports: {
    "./sso-oidc": {
      module: "./dist-es/submodules/sso-oidc/index.js",
      node: "./dist-cjs/submodules/sso-oidc/index.js",
      import: "./dist-es/submodules/sso-oidc/index.js",
      require: "./dist-cjs/submodules/sso-oidc/index.js",
      types: "./dist-types/submodules/sso-oidc/index.d.ts"
    },
    "./sts": {
      module: "./dist-es/submodules/sts/index.js",
      node: "./dist-cjs/submodules/sts/index.js",
      import: "./dist-es/submodules/sts/index.js",
      require: "./dist-cjs/submodules/sts/index.js",
      types: "./dist-types/submodules/sts/index.d.ts"
    }
  }
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/ruleset.js
var u = "required";
var v = "fn";
var w = "argv";
var x = "ref";
var a = true;
var b = "isSet";
var c = "booleanEquals";
var d = "error";
var e = "endpoint";
var f = "tree";
var g = "PartitionResult";
var h = "getAttr";
var i = { [u]: false, "type": "String" };
var j = { [u]: true, "default": false, "type": "Boolean" };
var k = { [x]: "Endpoint" };
var l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] };
var m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] };
var n = {};
var o = { [v]: h, [w]: [{ [x]: g }, "supportsFIPS"] };
var p = { [x]: g };
var q = { [v]: c, [w]: [true, { [v]: h, [w]: [p, "supportsDualStack"] }] };
var r = [l];
var s = [m];
var t = [{ [x]: "Region" }];
var _data = { version: "1.0", parameters: { Region: i, UseDualStack: j, UseFIPS: j, Endpoint: i }, rules: [{ conditions: [{ [v]: b, [w]: [k] }], rules: [{ conditions: r, error: "Invalid Configuration: FIPS and custom endpoint are not supported", type: d }, { conditions: s, error: "Invalid Configuration: Dualstack and custom endpoint are not supported", type: d }, { endpoint: { url: k, properties: n, headers: n }, type: e }], type: f }, { conditions: [{ [v]: b, [w]: t }], rules: [{ conditions: [{ [v]: "aws.partition", [w]: t, assign: g }], rules: [{ conditions: [l, m], rules: [{ conditions: [{ [v]: c, [w]: [a, o] }, q], rules: [{ endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS and DualStack are enabled, but this partition does not support one or both", type: d }], type: f }, { conditions: r, rules: [{ conditions: [{ [v]: c, [w]: [o, a] }], rules: [{ conditions: [{ [v]: "stringEquals", [w]: [{ [v]: h, [w]: [p, "name"] }, "aws-us-gov"] }], endpoint: { url: "https://oidc.{Region}.amazonaws.com", properties: n, headers: n }, type: e }, { endpoint: { url: "https://oidc-fips.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "FIPS is enabled but this partition does not support FIPS", type: d }], type: f }, { conditions: s, rules: [{ conditions: [q], rules: [{ endpoint: { url: "https://oidc.{Region}.{PartitionResult#dualStackDnsSuffix}", properties: n, headers: n }, type: e }], type: f }, { error: "DualStack is enabled but this partition does not support DualStack", type: d }], type: f }, { endpoint: { url: "https://oidc.{Region}.{PartitionResult#dnsSuffix}", properties: n, headers: n }, type: e }], type: f }], type: f }, { error: "Invalid Configuration: Missing Region", type: d }] };
var ruleSet = _data;

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/endpoint/endpointResolver.js
var cache = new EndpointCache({
  size: 50,
  params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"]
});
var defaultEndpointResolver = (endpointParams, context = {}) => {
  return cache.get(endpointParams, () => resolveEndpoint(ruleSet, {
    endpointParams,
    logger: context.logger
  }));
};
customEndpointFunctions.aws = awsEndpointFunctions;

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.shared.js
var getRuntimeConfig = (config) => {
  return {
    apiVersion: "2019-06-10",
    base64Decoder: config?.base64Decoder ?? fromBase64,
    base64Encoder: config?.base64Encoder ?? toBase64,
    disableHostPrefix: config?.disableHostPrefix ?? false,
    endpointProvider: config?.endpointProvider ?? defaultEndpointResolver,
    extensions: config?.extensions ?? [],
    httpAuthSchemeProvider: config?.httpAuthSchemeProvider ?? defaultSSOOIDCHttpAuthSchemeProvider,
    httpAuthSchemes: config?.httpAuthSchemes ?? [
      {
        schemeId: "aws.auth#sigv4",
        identityProvider: (ipc) => ipc.getIdentityProvider("aws.auth#sigv4"),
        signer: new AwsSdkSigV4Signer()
      },
      {
        schemeId: "smithy.api#noAuth",
        identityProvider: (ipc) => ipc.getIdentityProvider("smithy.api#noAuth") || (async () => ({})),
        signer: new NoAuthSigner()
      }
    ],
    logger: config?.logger ?? new NoOpLogger(),
    serviceId: config?.serviceId ?? "SSO OIDC",
    urlParser: config?.urlParser ?? parseUrl,
    utf8Decoder: config?.utf8Decoder ?? fromUtf8,
    utf8Encoder: config?.utf8Encoder ?? toUtf8
  };
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeConfig.js
var getRuntimeConfig2 = (config) => {
  emitWarningIfUnsupportedVersion2(process.version);
  const defaultsMode = resolveDefaultsModeConfig(config);
  const defaultConfigProvider = () => defaultsMode().then(loadConfigsForDefaultMode);
  const clientSharedValues = getRuntimeConfig(config);
  emitWarningIfUnsupportedVersion(process.version);
  const profileConfig = { profile: config?.profile };
  return {
    ...clientSharedValues,
    ...config,
    runtime: "node",
    defaultsMode,
    bodyLengthChecker: config?.bodyLengthChecker ?? calculateBodyLength,
    defaultUserAgentProvider: config?.defaultUserAgentProvider ?? createDefaultUserAgentProvider({ serviceId: clientSharedValues.serviceId, clientVersion: package_default.version }),
    maxAttempts: config?.maxAttempts ?? loadConfig(NODE_MAX_ATTEMPT_CONFIG_OPTIONS, config),
    region: config?.region ?? loadConfig(NODE_REGION_CONFIG_OPTIONS, { ...NODE_REGION_CONFIG_FILE_OPTIONS, ...profileConfig }),
    requestHandler: NodeHttpHandler.create(config?.requestHandler ?? defaultConfigProvider),
    retryMode: config?.retryMode ?? loadConfig({
      ...NODE_RETRY_MODE_CONFIG_OPTIONS,
      default: async () => (await defaultConfigProvider()).retryMode || DEFAULT_RETRY_MODE
    }, config),
    sha256: config?.sha256 ?? Hash.bind(null, "sha256"),
    streamCollector: config?.streamCollector ?? streamCollector,
    useDualstackEndpoint: config?.useDualstackEndpoint ?? loadConfig(NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS, profileConfig),
    useFipsEndpoint: config?.useFipsEndpoint ?? loadConfig(NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS, profileConfig),
    userAgentAppId: config?.userAgentAppId ?? loadConfig(NODE_APP_ID_CONFIG_OPTIONS, profileConfig)
  };
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/auth/httpAuthExtensionConfiguration.js
var getHttpAuthExtensionConfiguration = (runtimeConfig) => {
  const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
  let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
  let _credentials = runtimeConfig.credentials;
  return {
    setHttpAuthScheme(httpAuthScheme) {
      const index = _httpAuthSchemes.findIndex((scheme) => scheme.schemeId === httpAuthScheme.schemeId);
      if (index === -1) {
        _httpAuthSchemes.push(httpAuthScheme);
      } else {
        _httpAuthSchemes.splice(index, 1, httpAuthScheme);
      }
    },
    httpAuthSchemes() {
      return _httpAuthSchemes;
    },
    setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
      _httpAuthSchemeProvider = httpAuthSchemeProvider;
    },
    httpAuthSchemeProvider() {
      return _httpAuthSchemeProvider;
    },
    setCredentials(credentials) {
      _credentials = credentials;
    },
    credentials() {
      return _credentials;
    }
  };
};
var resolveHttpAuthRuntimeConfig = (config) => {
  return {
    httpAuthSchemes: config.httpAuthSchemes(),
    httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
    credentials: config.credentials()
  };
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/runtimeExtensions.js
var asPartial = (t2) => t2;
var resolveRuntimeExtensions = (runtimeConfig, extensions) => {
  const extensionConfiguration = {
    ...asPartial(getAwsRegionExtensionConfiguration(runtimeConfig)),
    ...asPartial(getDefaultExtensionConfiguration(runtimeConfig)),
    ...asPartial(getHttpHandlerExtensionConfiguration(runtimeConfig)),
    ...asPartial(getHttpAuthExtensionConfiguration(runtimeConfig))
  };
  extensions.forEach((extension) => extension.configure(extensionConfiguration));
  return {
    ...runtimeConfig,
    ...resolveAwsRegionExtensionConfiguration(extensionConfiguration),
    ...resolveDefaultRuntimeConfig(extensionConfiguration),
    ...resolveHttpHandlerRuntimeConfig(extensionConfiguration),
    ...resolveHttpAuthRuntimeConfig(extensionConfiguration)
  };
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDCClient.js
var SSOOIDCClient = class extends Client {
  config;
  constructor(...[configuration]) {
    const _config_0 = getRuntimeConfig2(configuration || {});
    const _config_1 = resolveClientEndpointParameters(_config_0);
    const _config_2 = resolveUserAgentConfig(_config_1);
    const _config_3 = resolveRetryConfig(_config_2);
    const _config_4 = resolveRegionConfig(_config_3);
    const _config_5 = resolveHostHeaderConfig(_config_4);
    const _config_6 = resolveEndpointConfig(_config_5);
    const _config_7 = resolveHttpAuthSchemeConfig(_config_6);
    const _config_8 = resolveRuntimeExtensions(_config_7, configuration?.extensions || []);
    super(_config_8);
    this.config = _config_8;
    this.middlewareStack.use(getUserAgentPlugin(this.config));
    this.middlewareStack.use(getRetryPlugin(this.config));
    this.middlewareStack.use(getContentLengthPlugin(this.config));
    this.middlewareStack.use(getHostHeaderPlugin(this.config));
    this.middlewareStack.use(getLoggerPlugin(this.config));
    this.middlewareStack.use(getRecursionDetectionPlugin(this.config));
    this.middlewareStack.use(getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
      httpAuthSchemeParametersProvider: defaultSSOOIDCHttpAuthSchemeParametersProvider,
      identityProviderConfigProvider: async (config) => new DefaultIdentityProviderConfig({
        "aws.auth#sigv4": config.credentials
      })
    }));
    this.middlewareStack.use(getHttpSigningPlugin(this.config));
  }
  destroy() {
    super.destroy();
  }
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/SSOOIDCServiceException.js
var SSOOIDCServiceException = class _SSOOIDCServiceException extends ServiceException {
  constructor(options) {
    super(options);
    Object.setPrototypeOf(this, _SSOOIDCServiceException.prototype);
  }
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/models/models_0.js
var AccessDeniedException = class _AccessDeniedException extends SSOOIDCServiceException {
  name = "AccessDeniedException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "AccessDeniedException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _AccessDeniedException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var AuthorizationPendingException = class _AuthorizationPendingException extends SSOOIDCServiceException {
  name = "AuthorizationPendingException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "AuthorizationPendingException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _AuthorizationPendingException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var CreateTokenRequestFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.clientSecret && { clientSecret: SENSITIVE_STRING },
  ...obj.refreshToken && { refreshToken: SENSITIVE_STRING },
  ...obj.codeVerifier && { codeVerifier: SENSITIVE_STRING }
});
var CreateTokenResponseFilterSensitiveLog = (obj) => ({
  ...obj,
  ...obj.accessToken && { accessToken: SENSITIVE_STRING },
  ...obj.refreshToken && { refreshToken: SENSITIVE_STRING },
  ...obj.idToken && { idToken: SENSITIVE_STRING }
});
var ExpiredTokenException = class _ExpiredTokenException extends SSOOIDCServiceException {
  name = "ExpiredTokenException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "ExpiredTokenException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _ExpiredTokenException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var InternalServerException = class _InternalServerException extends SSOOIDCServiceException {
  name = "InternalServerException";
  $fault = "server";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "InternalServerException",
      $fault: "server",
      ...opts
    });
    Object.setPrototypeOf(this, _InternalServerException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var InvalidClientException = class _InvalidClientException extends SSOOIDCServiceException {
  name = "InvalidClientException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "InvalidClientException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidClientException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var InvalidGrantException = class _InvalidGrantException extends SSOOIDCServiceException {
  name = "InvalidGrantException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "InvalidGrantException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidGrantException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var InvalidRequestException = class _InvalidRequestException extends SSOOIDCServiceException {
  name = "InvalidRequestException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "InvalidRequestException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidRequestException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var InvalidScopeException = class _InvalidScopeException extends SSOOIDCServiceException {
  name = "InvalidScopeException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "InvalidScopeException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _InvalidScopeException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var SlowDownException = class _SlowDownException extends SSOOIDCServiceException {
  name = "SlowDownException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "SlowDownException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _SlowDownException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var UnauthorizedClientException = class _UnauthorizedClientException extends SSOOIDCServiceException {
  name = "UnauthorizedClientException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "UnauthorizedClientException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _UnauthorizedClientException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};
var UnsupportedGrantTypeException = class _UnsupportedGrantTypeException extends SSOOIDCServiceException {
  name = "UnsupportedGrantTypeException";
  $fault = "client";
  error;
  error_description;
  constructor(opts) {
    super({
      name: "UnsupportedGrantTypeException",
      $fault: "client",
      ...opts
    });
    Object.setPrototypeOf(this, _UnsupportedGrantTypeException.prototype);
    this.error = opts.error;
    this.error_description = opts.error_description;
  }
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/protocols/Aws_restJson1.js
var se_CreateTokenCommand = async (input, context) => {
  const b2 = requestBuilder(input, context);
  const headers = {
    "content-type": "application/json"
  };
  b2.bp("/token");
  let body;
  body = JSON.stringify(take(input, {
    clientId: [],
    clientSecret: [],
    code: [],
    codeVerifier: [],
    deviceCode: [],
    grantType: [],
    redirectUri: [],
    refreshToken: [],
    scope: (_) => _json(_)
  }));
  b2.m("POST").h(headers).b(body);
  return b2.build();
};
var de_CreateTokenCommand = async (output, context) => {
  if (output.statusCode !== 200 && output.statusCode >= 300) {
    return de_CommandError(output, context);
  }
  const contents = map({
    $metadata: deserializeMetadata(output)
  });
  const data = expectNonNull(expectObject(await parseJsonBody(output.body, context)), "body");
  const doc = take(data, {
    accessToken: expectString,
    expiresIn: expectInt32,
    idToken: expectString,
    refreshToken: expectString,
    tokenType: expectString
  });
  Object.assign(contents, doc);
  return contents;
};
var de_CommandError = async (output, context) => {
  const parsedOutput = {
    ...output,
    body: await parseJsonErrorBody(output.body, context)
  };
  const errorCode = loadRestJsonErrorCode(output, parsedOutput.body);
  switch (errorCode) {
    case "AccessDeniedException":
    case "com.amazonaws.ssooidc#AccessDeniedException":
      throw await de_AccessDeniedExceptionRes(parsedOutput, context);
    case "AuthorizationPendingException":
    case "com.amazonaws.ssooidc#AuthorizationPendingException":
      throw await de_AuthorizationPendingExceptionRes(parsedOutput, context);
    case "ExpiredTokenException":
    case "com.amazonaws.ssooidc#ExpiredTokenException":
      throw await de_ExpiredTokenExceptionRes(parsedOutput, context);
    case "InternalServerException":
    case "com.amazonaws.ssooidc#InternalServerException":
      throw await de_InternalServerExceptionRes(parsedOutput, context);
    case "InvalidClientException":
    case "com.amazonaws.ssooidc#InvalidClientException":
      throw await de_InvalidClientExceptionRes(parsedOutput, context);
    case "InvalidGrantException":
    case "com.amazonaws.ssooidc#InvalidGrantException":
      throw await de_InvalidGrantExceptionRes(parsedOutput, context);
    case "InvalidRequestException":
    case "com.amazonaws.ssooidc#InvalidRequestException":
      throw await de_InvalidRequestExceptionRes(parsedOutput, context);
    case "InvalidScopeException":
    case "com.amazonaws.ssooidc#InvalidScopeException":
      throw await de_InvalidScopeExceptionRes(parsedOutput, context);
    case "SlowDownException":
    case "com.amazonaws.ssooidc#SlowDownException":
      throw await de_SlowDownExceptionRes(parsedOutput, context);
    case "UnauthorizedClientException":
    case "com.amazonaws.ssooidc#UnauthorizedClientException":
      throw await de_UnauthorizedClientExceptionRes(parsedOutput, context);
    case "UnsupportedGrantTypeException":
    case "com.amazonaws.ssooidc#UnsupportedGrantTypeException":
      throw await de_UnsupportedGrantTypeExceptionRes(parsedOutput, context);
    default:
      const parsedBody = parsedOutput.body;
      return throwDefaultError({
        output,
        parsedBody,
        errorCode
      });
  }
};
var throwDefaultError = withBaseException(SSOOIDCServiceException);
var de_AccessDeniedExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new AccessDeniedException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_AuthorizationPendingExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new AuthorizationPendingException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_ExpiredTokenExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new ExpiredTokenException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InternalServerExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new InternalServerException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidClientExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidClientException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidGrantExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidGrantException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidRequestExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidRequestException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_InvalidScopeExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new InvalidScopeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_SlowDownExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new SlowDownException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_UnauthorizedClientExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new UnauthorizedClientException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var de_UnsupportedGrantTypeExceptionRes = async (parsedOutput, context) => {
  const contents = map({});
  const data = parsedOutput.body;
  const doc = take(data, {
    error: expectString,
    error_description: expectString
  });
  Object.assign(contents, doc);
  const exception = new UnsupportedGrantTypeException({
    $metadata: deserializeMetadata(parsedOutput),
    ...contents
  });
  return decorateServiceException(exception, parsedOutput.body);
};
var deserializeMetadata = (output) => ({
  httpStatusCode: output.statusCode,
  requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
  extendedRequestId: output.headers["x-amz-id-2"],
  cfId: output.headers["x-amz-cf-id"]
});

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/commands/CreateTokenCommand.js
var CreateTokenCommand = class extends Command.classBuilder().ep(commonParams).m(function(Command2, cs, config, o2) {
  return [
    getSerdePlugin(config, this.serialize, this.deserialize),
    getEndpointPlugin(config, Command2.getEndpointParameterInstructions())
  ];
}).s("AWSSSOOIDCService", "CreateToken", {}).n("SSOOIDCClient", "CreateTokenCommand").f(CreateTokenRequestFilterSensitiveLog, CreateTokenResponseFilterSensitiveLog).ser(se_CreateTokenCommand).de(de_CreateTokenCommand).build() {
};

// ../../node_modules/@aws-sdk/client-bedrock-runtime/node_modules/@aws-sdk/credential-provider-node/node_modules/@aws-sdk/credential-provider-sso/node_modules/@aws-sdk/token-providers/node_modules/@aws-sdk/nested-clients/dist-es/submodules/sso-oidc/SSOOIDC.js
var commands = {
  CreateTokenCommand
};
var SSOOIDC = class extends SSOOIDCClient {
};
createAggregatedClient(commands, SSOOIDC);
export {
  Command as $Command,
  AccessDeniedException,
  AuthorizationPendingException,
  CreateTokenCommand,
  CreateTokenRequestFilterSensitiveLog,
  CreateTokenResponseFilterSensitiveLog,
  ExpiredTokenException,
  InternalServerException,
  InvalidClientException,
  InvalidGrantException,
  InvalidRequestException,
  InvalidScopeException,
  SSOOIDC,
  SSOOIDCClient,
  SSOOIDCServiceException,
  SlowDownException,
  UnauthorizedClientException,
  UnsupportedGrantTypeException,
  Client as __Client
};
//# sourceMappingURL=sso-oidc-ZMLZ6ZZM.js.map