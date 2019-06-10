PACKAGE=        tests

TESTSDIR=       ${TESTSBASE}/sys/mac/ipacl

${PACKAGE}FILES+=       ipacl_script.sh

TAP_TESTS_SH+=  ipacl_test

.for t in ${TAP_TESTS_SH}
TEST_METADATA.$t+=      required_user="root"
TEST_METADATA.$t+=      timeout="450"
.endfor

.include <bsd.test.mk>
