package nat;

use strict;
use warnings;
our @EXPORT_OK;
our @routers = ( "england", "france", "germany", "holland" );

#list of service PIC nexthops per router, separated by space
our @spics = ( "sp-1/3/0", "sp-1/3/0", "sp-1/2/0", "sp" );

our $subscriber_pools = "192.168.1.0/25 192.168.128.0/25";

our @external_pools = ( "100.1.1.1/32", "100.1.1.2/32", "100.1.1.2/32" );

BEGIN {
	require Exporter;

	use constant N_ROUTERS                   => 3;
	use constant L3_UNIT_INSIDE              => 1;
	use constant L3_UNIT_OUTSIDE             => 2;
	use constant RI_PREFIX                   => "ri";
	use constant NAME_SEPARATOR              => "-";
	use constant VRF_TARGET_PREFIX           => "target:100:";
	use constant VRF_TARGET_FIRST            => 101;
	use constant SPRAY_FILTER_NAME           => "flt-spray";
	use constant SPRAY_FILTER_COUNTER_PREFIX => "cnt";
	use constant CONFIG_PREFIX               => "replace: ";
	use constant SP_RIB_GROUP_NAME           => "sp-intf";
	use constant RIB_IMPORT_POLICY           => "p-import-sp";
	use constant VRF_POLICY_PREFIX           => "p-exp";
	use constant COMMUNITY_PREFIX            => "c";
	use constant VRF_BACKUP_SUFFIX           => "backup";
	use constant VRF_POLICY_NULL_IMPORT      => "p-import-none";
	use constant BACKUP_my_PREFERENCE        => 90;
	use constant POOL_PREFIX_LIST_NAME       => "pl-nat-my-pool";
	use constant FILTER_INSIDE               => "flt-inside";
	use constant COUNT_TRANSLATED            => "cnt-translated";
	use constant COUNT_NON_SUBSCRIBERS       => "cnt-non-subscribers";

	use constant NAT_RULE_PREFIX    => "rule-";
	use constant SERVICE_SET_PREFIX => "ss-";

	# preference for the backup routes
	use constant BACKUP_ROUTE_PREFERENCE => 180;

	# MASK_BITS should be less than or equal to 8
	use constant MASK_BITS => 5;
	@EXPORT_OK =
	  qw ( get_routers get_service_pics get_subscriber_pools get_external_pools);
}

sub get_routers {
	return @routers;
}

sub get_service_pics {
	return @spics;
}

sub get_subscriber_pools {
	return $subscriber_pools;
}

sub get_external_pools {
	return @external_pools;
}
