#!/usr/bin/php
<?php
/**
 * Copy to /usr/local/bin/ or wherever and set up the list in main.cf:
 * postscreen_access_list = permit_mynetworks,
 *        cidr:/etc/postfix/postscreen_dynamic_access.cidr
 *
 * Usage: spfcidr.php > /etc/postfix/postscreen_access_dynamic.cidr
 * Remember to reload postfix as part of the routine.
 */

$whitelist = array(
    'google.com',
    'ebay.co.uk',
    'amazon.co.uk'
);

/**
 * Some spf includes may not be needed. Add them to this array.
 */
$exclude = array(
    'salesforce.com'
);



foreach ($whitelist as $mxdomain) {
    getIpAddresses($mxdomain, $exclude);
}


/**
 * Retrieve all records that may contain ip addresses. Prints out domain as a comment
 * followed by cidr lookup table style printing of ip addresses/blocks.
 *
 * @param string $domain  Domain to add to whitelist
 * @param array  $exclude Array of domains to exclude from whitelist
 * @param array  &$unique Array of cidrs already retrieved
 *
 * @return void
 */
function getIpAddresses($domain, Array $exclude = array(), Array &$unique=array())
{
    printf("# %s\n", $domain);
    foreach (dns_get_record($domain, DNS_TXT) as $resultset) {
        preg_match_all('/ip(4|6):([^ ]+)/', $resultset['txt'], $matches);
        foreach ($matches[2] as $record) {
            if (!in_array($record, $unique)) {
                $unique[] = $record;
                printf("%s\tpermit\n", $record);
            }
        }
        preg_match_all('/include:([^ ]+)/', $resultset['txt'], $matches);
        if (is_array($matches[1])) {
            foreach ($matches[1] as $subdomain) {
                if (!in_array($subdomain, $exclude)) {
                    getIpAddresses($subdomain, $exclude, $unique);
                }
            }
        }

    }
}
