module.exports = {
  env: {
    node: true
  },
  extends: [
    'digitalbazaar',
    'eslint-config-digitalbazaar',
    'digitalbazaar/jsdoc'
  ],
  root: true,
  ignorePatterns: ['node_modules/']
};
