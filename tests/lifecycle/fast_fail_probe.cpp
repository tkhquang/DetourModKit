// Fast-failing control probe for the CTest timeout-control NEGATIVE proof (CTestTimeoutControlNegative). It exits
// nonzero immediately -- never by timeout -- so the verifier must REJECT it: the failure is not a timeout. The negative
// proof is WILL_FAIL, so it passes only when the verifier correctly FATALs on this non-timeout failure, which locks the
// verifier's "***Timeout"-token match against a regression to a bare-word "timeout" match that a scratch path
// containing "timeout" would false-satisfy.

int main()
{
    return 1;
}
