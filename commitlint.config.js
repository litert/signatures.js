module.exports = {
    'extends': ['@commitlint/config-conventional'],
    'defaultIgnores': false,
    'rules': {
        'type-enum': [2, 'always', [
            'feat',
            'fix',
            'add',
            'build',
            'merge',
            'deprecate'
        ]],
        'scope-enum': [2, 'always', [
            'hash',
            'hmac',
            'ecdsa',
            'rsa',
            'test',
            'bug',
            'lint',
            'branch',
            'project'
        ]],
        'scope-empty': [2, 'never'],
        'subject-min-length': [2, 'always', 5],
        'subject-max-length': [2, 'always', 50],
    }
};
