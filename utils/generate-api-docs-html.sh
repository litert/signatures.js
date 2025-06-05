#!/usr/bin/env bash
SCRIPT_ROOT=$(cd $(dirname $0); pwd)

cd $SCRIPT_ROOT/..

WORK_DIR=$SCRIPT_ROOT/../tmp
DOC_DIRNAME=api-docs
API_DOC_OUTPUT_DIR=$WORK_DIR/$DOC_DIRNAME
SRC_DIR=src/lib

if [[ -n $(git status --porcelain $SRC_DIR) ]]; then
    echo "Error: You have unstaged changes. Please commit or stash them before generating API docs."
    exit 1
fi

rm -rf $API_DOC_OUTPUT_DIR

npx typedoc \
    --out $API_DOC_OUTPUT_DIR \
    --readme none \
    --name "Documents for @litert/signatures" \
    --sourceLinkTemplate "https://github.com/litert/signatures.js/blob/master/{path}#L{line}" \
    $SRC_DIR/index.ts \
    $SRC_DIR/Errors.ts \
    $SRC_DIR/Hash.ts \
    $SRC_DIR/HMAC.ts \
    $SRC_DIR/EDDSA.ts \
    $SRC_DIR/Decl.ts \
    $SRC_DIR/ECDSA/*.ts \
    $SRC_DIR/RSA/*.ts

cd $WORK_DIR

tar -zcf api-docs.tgz $DOC_DIRNAME

rm -rf $DOC_DIRNAME

cd $SCRIPT_ROOT/..

git checkout $SRC_DIR
