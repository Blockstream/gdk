#include <mutex>

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "network_parameters.hpp"

// TODO: Use std::string_view when its fully supported

// clang-format off
namespace {

static std::vector<std::string> wamp_cert_roots = {

// TODO: generate these from pem file?
// https://www.identrust.com/certificates/trustid/root-download-x3.html
//
// subject: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
// issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
// not before: Sat Sep 30 21:12:19 2000
// not after: Thu Sep 30 14:01:15 2021
R"(
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----)",

// https://letsencrypt.org/certificates/
//
// subject: '/C=US/O=Let's Encrypt/CN=R3'
// issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
// not before: Wed Oct  7 19:21:40 2020
// not after: Wed Sep 29 19:21:40 2021
R"(
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMUpMghjISpDBbN3zANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0MFoXDTIxMDkyOTE5MjE0MFow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwIVKMz2oJTTDxLs
jVWSw/iC8ZmmekKIp10mqrUrucVMsa+Oa/l1yKPXD0eUFFU1V4yeqKI5GfWCPEKp
Tm71O8Mu243AsFzzWTjn7c9p8FoLG77AlCQlh/o3cbMT5xys4Zvv2+Q7RVJFlqnB
U840yFLuta7tj95gcOKlVKu2bQ6XpUA0ayvTvGbrZjR8+muLj1cpmfgwF126cm/7
gcWt0oZYPRfH5wm78Sv3htzB2nFd1EbjzK0lwYi8YGd1ZrPxGPeiXOZT/zqItkel
/xMY6pgJdz+dU/nPAeX1pnAXFK9jpP+Zs5Od3FOnBv5IhR2haa4ldbsTzFID9e1R
oYvbFQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYf
r52LFMLGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEA2UzgyfWEiDcx27sT4rP8i2tiEmxYt0l+PAK3qB8oYevO4C5z70kH
ejWEHx2taPDY/laBL21/WKZuNTYQHHPD5b1tXgHXbnL7KqC401dk5VvCadTQsvd8
S8MXjohyc9z9/G2948kLjmE6Flh9dDYrVYA9x2O+hEPGOaEOa1eePynBgPayvUfL
qjBstzLhWVQLGAkXXmNs+5ZnPBxzDJOLxhF2JIbeQAcH5H0tZrUlo5ZYyOqA7s9p
O5b85o3AM/OJ+CktFBQtfvBhcJVd9wvlwPsk+uyOy2HI7mNxKKgsBTt375teA2Tw
UdHkhVNcsAKX1H7GNNLOEADksd86wuoXvg==
-----END CERTIFICATE-----)",

// backup
//
// subject: '/C=US/O=Let's Encrypt/CN=R4'
// issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
// not before: Wed Oct  7 19:21:45 2020
// not after: Wed Sep 29 19:21:45 2021
R"(
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMlO+Rkt3exI9CKgjANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0NVoXDTIxMDkyOTE5MjE0NVow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlI0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsyjcdynT55G+87cK
AMf78lULJSJjUzav6Qgg3w2vKD7NxqtXtp2kJRml0jJtSaYIuccvoZuTxSBAa4Qx
IKKOMGAlYO/ZGok/H2lxstrqP3NBxJBvZv19nljYd8/NWXVEyaEKe58/Gw46Zm+2
dc+Ly6+dwHDF/9KCCq9dzeLonIWUpOYANeh+TjmBxyGJYHfqHZbyi4N7R8RtMsBS
fiMeRbVx7qPvF8IDqZOJ3fWf27rx2uB+l4dxgR4aglbkPnwYogjlFl+o+qjgSFFN
GBSgDKPltsqztVUSa3LHWn87jPnn2dGOEk0zMwMq8RPhQjzCLllgLm3gB0czZd/S
Z8pNhQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0x
ivZUpkYmMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEAN4CpgPmK2C5pq/RdV9gEdWcvPnPfT9ToucrAMTcn//wyWBWF2wG4
hvPBQxxuqPECZsi4nLQ45VJpyC1NDd0GqGQIMqNdC4N4TLDtd7Yhy8v5JsfEMUbb
6xW4sKeeeKy3afOkel60Xg1/7ndSmppiHqdh+TdJML1hptRgdxGiB8LMpHuW/oM8
akfyt4TkBhA8+Wu8MM6dlJyJ7nHBVnEUFQ4Ni+GzNC/pQSL2+Y9Mq4HHIk2ZFy0W
B8KsVwdeNrERPL+LjhhLde1Et0aL9nlv4CqwXHML2LPgk38j/WllbQ/8HRd2VpB+
JW6Z8JNhcnuBwATHMCeJVCFapoZsPfQQ6Q==
-----END CERTIFICATE-----)",

// subject: '/C=US/O=Let's Encrypt/CN=E1'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
// not before: Fri Sep  4 00:00:00 2020
// not after: Mon Sep 15 16:00:00 2025
R"(
-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----)",

// backup
//
// subject: '/C=US/O=Let's Encrypt/CN=E2'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
// not before: Fri Sep  4 00:00:00 2020
// not after: Mon Sep 15 16:00:00 2025
R"(
-----BEGIN CERTIFICATE-----
MIICxjCCAkygAwIBAgIQTtI99q9+x/mwxHJv+VEqdzAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw0y
NTA5MTUxNjAwMDBaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABCOaLO3lixmN
YVWex+ZVYOiTLgi0SgNWtU4hufk50VU4Zp/LbBVDxCsnsI7vuf4xp4Cu+ETNggGE
yBqJ3j8iUwe5Yt/qfSrRf1/D5R58duaJ+IvLRXeASRqEL+VkDXrW3qOCAQgwggEE
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUbZkq9U0C6+MRwWC6km+NPS7x
6kQwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5UwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wIgYDVR0gBBswGTAIBgZn
gQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZIzj0EAwMDaAAwZQIxAPJCN9qpyDmZ
tX8K3m8UYQvK51BrXclM6WfrdeZlUBKyhTXUmFAtJw4X6A0x9mQFPAIwJa/No+KQ
UAM1u34E36neL/Zba7ombkIOchSgx1iVxzqtFWGddgoG+tppRPWhuhhn
-----END CERTIFICATE-----)",

// subject: '/C=US/O=Google Trust Services LLC/CN=GTS Root R1'
// issuer: '/C=US/O=Google Trust Services LLC/CN=GTS Root R1'
// not before: Wed Jun 22 00:00:00 2016
// not after: Sun Jun 22 00:00:00 2036
R"(
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQbkepxUtHDA3sM9CJuRz04TANBgkqhkiG9w0BAQwFADBH
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIy
MDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNl
cnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaM
f/vo27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vX
mX7wCl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7
zUjwTcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0P
fyblqAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtc
vfaHszVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4
Zor8Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUsp
zBmkMiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOO
Rc92wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYW
k70paDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+
DVrNVjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgF
lQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBADiW
Cu49tJYeX++dnAsznyvgyv3SjgofQXSlfKqE1OXyHuY3UjKcC9FhHb8owbZEKTV1
d5iyfNm9dKyKaOOpMQkpAWBz40d8U6iQSifvS9efk+eCNs6aaAyC58/UEBZvXw6Z
XPYfcX3v73svfuo21pdwCxXu11xWajOl40k4DLh9+42FpLFZXvRq4d2h9mREruZR
gyFmxhE+885H7pwoHyXa/6xmld01D1zvICxi/ZG6qcz8WpyTgYMpl0p8WnK0OdC3
d8t5/Wk6kjftbjhlRn7pYL15iJdfOBL07q9bgsiG1eGZbYwE8na6SfZu6W0eX6Dv
J4J2QPim01hcDyxC2kLGe4g0x8HYRZvBPsVhHdljUEn2NIVq4BjFbkerQUIpm/Zg
DdIx02OYI5NaAIFItO/Nis3Jz5nu2Z6qNuFoS3FJFDYoOj0dzpqPJeaAcWErtXvM
+SUWgeExX6GjfhaknBZqlxi9dnKlC54dNuYvoS++cJEPqOba+MSSQGwlfnuzCdyy
F62ARPBopY+Udf90WuioAnwMCeKpSwughQtiue+hMZL77/ZRBIls6Kl0obsXs7X9
SQ98POyDGCBDTtWTurQ0sR8WNh8M5mQ5Fkzc4P4dyKliPUDqysU0ArSuiYgzNdws
E3PYJ/HQcu51OyLemGhmW/HGY0dVHLqlCFF1pkgl
-----END CERTIFICATE-----)",

// subject: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
// not before: Thu Jun  4 11:04:38 2015
// not after: Mon Jun  4 11:04:38 2035
R"(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----)",
};

static std::vector<std::string> wamp_cert_pins = {
    // subject: '/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3'
    // issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
    // not before: Thu Mar 17 16:40:46 2016
    // not after: Wed Mar 17 16:40:46 2021
    "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",

    // subject: '/C=US/O=Let's Encrypt/CN=R3'
    // issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
    // not before: Wed Oct  7 19:21:40 2020
    // not after: Wed Sep 29 19:21:40 2021
    "730c1bdcd85f57ce5dc0bba733e5f1ba5a925b2a771d640a26f7a454224dad3b",

    // subject: '/C=US/O=Let's Encrypt/CN=E1'
    // issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
    // not before: Fri Sep  4 00:00:00 2020
    // not after: Mon Sep 15 16:00:00 2025
    "46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda",

    // subject: '/C=US/O=Let's Encrypt/CN=R4'
    // issuer: '/O=Digital Signature Trust Co./CN=DST Root CA X3'
    // not before: Wed Oct  7 19:21:45 2020
    // not after: Wed Sep 29 19:21:45 2021
    "5a8f16fda448d783481cca57a2428d174dad8c60943ceb28f661ae31fd39a5fa",

    // ??
    "b42688d73bac5099d9cf4fdb7b05f5e54e98c5aa8ab56ee06c297a9a84d2d5f1",

    // subject: '/C=US/O=Let's Encrypt/CN=R3'
    // issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
    // not before: Fri Sep  4 00:00:00 2020
    // not after: Mon Sep 15 16:00:00 2025
    "67add1166b020ae61b8f5fc96813c04c2aa589960796865572a3c7e737613dfd",
};

static std::map<std::string, std::shared_ptr<nlohmann::json>> registered_networks = {
    { "localtest",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "bech32_prefix", "bcrt" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:19002" },
            { "liquid", false },
            { "mainnet", false },
            { "name", "Localtest" },
            { "network", "localtest" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", wamp_cert_roots },
            { "wamp_onion_url", std::string() },
            { "wamp_url", "ws://localhost:8080/v2/ws" }
        })) },

    { "liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/liquid/address/" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "bech32_prefix", "ex" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "lq" },
            { "blinded_prefix", 12u },
            { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } },
            { "ct_bits", 52 },
            { "ct_exponent", 0 },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:995" },
            { "liquid", true },
            { "mainnet", true },
            { "name", "Liquid" },
            { "network", "liquid" },
            { "p2pkh_version", 57u },
            { "p2sh_version", 39u },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "server_type", "green" },
            { "service_chain_code", "02721cc509aa0c2f4a90628e9da0391b196abeabc6393ed4789dd6222c43c489" },
            { "service_pubkey", "02c408c3bb8a3d526103fb93246f54897bdd997904d3e18295b49a26965cb41b7f" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" },
            { "wamp_cert_pins", wamp_cert_pins },
            { "wamp_cert_roots", wamp_cert_roots },
            { "wamp_onion_url", "ws://liquidbtc7u746j4.onion/v2/ws" },
            { "wamp_url", "wss://liquidwss.greenaddress.it/v2/ws" }
        })) },

    { "localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "bech32_prefix", "ert" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "el" },
            { "blinded_prefix", 4u },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 25920, 51840, 65535 } },
            { "ct_bits", 52 },
            { "ct_exponent", 0 },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:50001" },
            { "liquid", true },
            { "mainnet", false },
            { "name", "Localtest Liquid" },
            { "network", "localtest-liquid" },
            { "p2pkh_version", 235u },
            { "p2sh_version", 75u },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", wamp_cert_roots },
            { "wamp_onion_url", std::string() },
            { "wamp_url", "ws://localhost:8080/v2/ws" }
        })) },

    { "mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/address/" },
            { "bech32_prefix", "bc" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:700" },
            { "liquid", false },
            { "mainnet", true },
            { "name", "Bitcoin" },
            { "network", "mainnet" },
            { "p2pkh_version", 0u },
            { "p2sh_version", 5u },
            { "server_type", "green" },
            { "service_chain_code", "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d" },
            { "service_pubkey", "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/tx/" },
            { "wamp_cert_pins", wamp_cert_pins },
            { "wamp_cert_roots", wamp_cert_roots },
            { "wamp_onion_url", "ws://s7a4rvc6425y72d2.onion/v2/ws" },
            { "wamp_url", "wss://prodwss.greenaddress.it/v2/ws" }
        })) },

    { "testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "bech32_prefix", "tb" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:993" },
            { "liquid", false },
            { "mainnet", false },
            { "name", "Testnet" },
            { "network", "testnet" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
            { "wamp_cert_pins", wamp_cert_pins },
            { "wamp_cert_roots", wamp_cert_roots },
            { "wamp_onion_url", "ws://gu5ke7a2aguwfqhz.onion/v2/ws" },
            { "wamp_url", "wss://testwss.greenaddress.it/v2/ws" }
        })) },

#ifdef BUILD_GDK_RUST
    { "electrum-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/liquid/address/" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "bech32_prefix", "ex" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "lq" },
            { "blinded_prefix", 12u },
            { "csv_buckets", std::vector<uint32_t>() },
            { "ct_bits", 52 },
            { "ct_exponent", 0 },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:995" },
            { "liquid", true },
            { "mainnet", true },
            { "name", "Liquid (Electrum)" },
            { "network", "electrum-liquid" },
            { "p2pkh_version", 57u },
            { "p2sh_version", 39u },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array() },
            { "wamp_onion_url", std::string() },
            { "wamp_url", std::string() }
        })) },

    { "electrum-localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "bech32_prefix", "ert" },
            { "bip21_prefix", "liquidregtestnetwork" },
            { "blech32_prefix", "el" },
            { "blinded_prefix", 4u },
            { "csv_buckets", std::vector<uint32_t>() },
            { "ct_bits", 52 },
            { "ct_exponent", 0 },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:50001" },
            { "liquid", true },
            { "mainnet", false },
            { "name", "Localtest Liquid (Electrum)" },
            { "network", "electrum-localtest-liquid" },
            { "p2pkh_version", 235u },
            { "p2sh_version", 75u },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array() },
            { "wamp_onion_url", std::string() },
            { "wamp_url", std::string() }
        })) },

    { "electrum-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/address/" },
            { "bech32_prefix", "bc" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:700" },
            { "liquid", false },
            { "mainnet", true },
            { "name", "Bitcoin (Electrum)" },
            { "network", "electrum-mainnet" },
            { "p2pkh_version", 0u },
            { "p2sh_version", 5u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array() },
            { "wamp_onion_url", std::string() },
            { "wamp_url", std::string() },
        })) },

    { "electrum-testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "bech32_prefix", "tb" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "blockstream.info:993" },
            { "liquid", false },
            { "mainnet", false },
            { "name", "Testnet (Electrum)" },
            { "network", "electrum-testnet" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array() },
            { "wamp_onion_url", std::string() },
            { "wamp_url", std::string() },
        })) },

    { "electrum-localtest",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "http://127.0.0.1:8080/address/" },
            { "bech32_prefix", "bcrt" },
            { "bip21_prefix", "bitcoin" },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:50001" },
            { "liquid", false },
            { "mainnet", false },
            { "name", "Localtest (Electrum)" },
            { "network", "electrum-localtest" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "http://127.0.0.1:8080/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array() },
            { "wamp_onion_url", std::string() },
            { "wamp_url", std::string() },
        })) },
#endif
};
// clang-format on

static std::mutex registered_networks_mutex;
} // namespace

namespace ga {
namespace sdk {

    network_parameters::network_parameters(const nlohmann::json& details)
        : m_details(details)
    {
    }

    network_parameters::~network_parameters() = default;

    void network_parameters::add(const std::string& name, const nlohmann::json& details)
    {
        std::unique_lock<std::mutex> l{ registered_networks_mutex };

        const auto p = registered_networks.find(name);
        const bool found = p != registered_networks.end();
        if (details.is_null() || details.empty()) {
            // Remove
            if (found) {
                registered_networks.erase(p);
            }
        } else {
            // Validate and add, overwriting any existing entry
            auto np = std::make_shared<nlohmann::json>(network_parameters(details).get_json());
            registered_networks[name] = np;
        }
    }

    nlohmann::json network_parameters::get_all()
    {
        // We manually order mainnet/liquid/testnet first for nice wallet/UX display ordering
        std::vector<std::string> all_networks{ "mainnet", "liquid", "testnet" };
        nlohmann::json ret;

        std::unique_lock<std::mutex> l{ registered_networks_mutex };
        all_networks.reserve(registered_networks.size());
        for (const auto& p : registered_networks) {
            ret[p.first] = *p.second;
            if (std::find(all_networks.begin(), all_networks.end(), p.first) == all_networks.end()) {
                all_networks.emplace_back(p.first);
            }
        }
        ret["all_networks"] = all_networks;
        return ret;
    }

    nlohmann::json network_parameters::get(const std::string& name)
    {
        std::unique_lock<std::mutex> l{ registered_networks_mutex };

        const auto p = registered_networks.find(name);
        if (p == registered_networks.end()) {
            throw user_error("Unknown network");
        }
        return *p->second;
    }

    std::string network_parameters::network() const { return m_details.at("network"); }
    std::string network_parameters::gait_wamp_url() const { return m_details.at("wamp_url"); }
    std::vector<std::string> network_parameters::gait_wamp_cert_pins() const { return m_details.at("wamp_cert_pins"); }
    std::vector<std::string> network_parameters::gait_wamp_cert_roots() const
    {
        return m_details.at("wamp_cert_roots");
    }
    std::string network_parameters::block_explorer_address() const { return m_details.at("address_explorer_url"); }
    std::string network_parameters::block_explorer_tx() const { return m_details.at("tx_explorer_url"); }
    std::string network_parameters::asset_registry_url() const { return m_details.at("asset_registry_url"); }
    std::string network_parameters::asset_registry_onion_url() const
    {
        return m_details.at("asset_registry_onion_url");
    }
    std::string network_parameters::chain_code() const { return m_details.at("service_chain_code"); }
    bool network_parameters::electrum_tls() const { return m_details.at("electrum_tls"); }
    std::string network_parameters::electrum_url() const { return m_details.at("electrum_url"); }
    std::string network_parameters::pub_key() const { return m_details.at("service_pubkey"); }
    std::string network_parameters::gait_onion() const { return m_details.at("wamp_onion_url"); }
    std::string network_parameters::policy_asset() const { return m_details.value("policy_asset", std::string()); }
    std::string network_parameters::bip21_prefix() const { return m_details.at("bip21_prefix"); }
    std::string network_parameters::bech32_prefix() const { return m_details.at("bech32_prefix"); }
    std::string network_parameters::blech32_prefix() const { return m_details.at("blech32_prefix"); }
    std::string network_parameters::log_level() const { return m_details.value("log_level", "none"); }
    unsigned char network_parameters::btc_version() const { return m_details.at("p2pkh_version"); }
    unsigned char network_parameters::btc_p2sh_version() const { return m_details.at("p2sh_version"); }
    uint32_t network_parameters::blinded_prefix() const { return m_details.at("blinded_prefix"); }
    int network_parameters::ct_exponent() const { return m_details.at("ct_exponent"); }
    int network_parameters::ct_bits() const { return m_details.at("ct_bits"); }
    bool network_parameters::is_main_net() const { return m_details.at("mainnet"); }
    bool network_parameters::is_liquid() const { return m_details.value("liquid", false); }
    bool network_parameters::is_electrum() const { return m_details.value("server_type", std::string()) == "electrum"; }
    bool network_parameters::use_tor() const { return m_details.value("use_tor", false); }
    std::string network_parameters::socks5() const { return m_details.value("socks5", std::string()); }
    bool network_parameters::spv_enabled() const { return m_details.at("spv_enabled"); }
    std::string network_parameters::user_agent() const { return m_details.value("user_agent", std::string()); }
    std::string network_parameters::get_connection_string() const { return use_tor() ? gait_onion() : gait_wamp_url(); }
    std::string network_parameters::get_registry_connection_string() const
    {
        return use_tor() ? asset_registry_onion_url() : asset_registry_url();
    }
    bool network_parameters::is_tls_connection() const
    {
        return boost::algorithm::starts_with(get_connection_string(), "wss://");
    }
    std::vector<uint32_t> network_parameters::csv_buckets() const { return m_details.at("csv_buckets"); }

} // namespace sdk
} // namespace ga
