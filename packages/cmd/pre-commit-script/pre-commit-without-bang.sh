

# MANAGED BY INFISICAL CLI (Do not modify): START
kmsScanEnabled=$(git config --bool hooks.kms-scan)

if [ "$kmsScanEnabled" != "false" ]; then
    kms scan git-changes -v --staged
    exitCode=$?
    if [ $exitCode -eq 1 ]; then
        echo "Commit blocked: Hanzo KMS scan has uncovered secrets in your git commit"
        echo "To disable the Hanzo KMS scan precommit hook run the following command:"
        echo ""
        echo "    git config hooks.kms-scan false"
        echo ""
        exit 1
    fi
else
    echo 'Warning: kms scan precommit disabled'
fi
# MANAGED BY INFISICAL CLI (Do not modify): END