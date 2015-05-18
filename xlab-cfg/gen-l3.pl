#!/usr/bin/perl 
use POSIX;
use nat;

my @routers = nat::get_routers();

#list of service PIC nexthops per router, separated by space
my @spics = nat::get_service_pics();

my $subscriber_pools = nat::get_subscriber_pools();

my @spics_inside;

# prepare list of PIC inside interfaces

for ( my $r = 0 ; $r < nat::N_ROUTERS ; $r++ ) {
	my @s = split / /, $spics[$r];

	for ( my $i = 0 ; $i < @s ; $i++ ) {
		$s[$i] = sprintf "%s.%d", $s[$i], nat::L3_UNIT_INSIDE;
	}
	$spics_inside[$r] = join( ' ', @s );
}

for ( my $r = 0 ; $r < nat::N_ROUTERS ; $r++ ) {
	my $f;
	my $router_name = $routers[$r];
	open( $f, '>', "$router_name-l3.cfg" );
	gen_filters( $r, $f );
	gen_routing_instances( $r, $f );
	gen_policies( $r, $f );
	gen_rib_groups( $r, $f );
	close($f);
}

sub gen_rib_groups {
	my $r = shift;
	my $f = shift;

	printf $f "routing-options {\n";
	printf $f "\t%sinterface-routes {\n", nat::CONFIG_PREFIX;
	printf $f "\t\trib-group inet %s;\n", nat::SP_RIB_GROUP_NAME;
	printf $f "\t}\n";

	printf $f "\t%srib-groups\n", nat::CONFIG_PREFIX;
	printf $f "\t\t%s {\n",       nat::SP_RIB_GROUP_NAME;

	printf $f "\t\t\timport-rib [ inet.0 %s%s%s%s%s.inet.0 ", nat::RI_PREFIX,
	  nat::NAME_SEPARATOR, $routers[$r], nat::NAME_SEPARATOR,
	  nat::VRF_BACKUP_SUFFIX;
	for ( my $j = 0 ; $j < nat::N_ROUTERS ; $j++ ) {
		if ( $r != $j ) {
			printf $f "%s%s%s%s%s.inet.0 ", nat::RI_PREFIX, nat::NAME_SEPARATOR,
			  $routers[$r], nat::NAME_SEPARATOR, $routers[$j];
			printf $f "%s%s%s%s%s.inet.0 ", nat::RI_PREFIX, nat::NAME_SEPARATOR,
			  $routers[$j], nat::NAME_SEPARATOR, $routers[$r];
		}
	}
	printf $f "];\n";
	printf $f "\t\t\timport-policy %s;\n", nat::RIB_IMPORT_POLICY;
	printf $f "\t\t}\n";
	printf $f "}\n";
}

sub gen_routing_instances {
	my $r          = shift;
	my $f          = shift;
	my $vrf_target = nat::VRF_TARGET_FIRST;
	printf $f "%srouting-instances {\n", nat::CONFIG_PREFIX;

	#generate main traffic distribution instances
	for ( my $i = 0 ; $i < nat::N_ROUTERS ; $i++ ) {
		for ( my $j = 0 ; $j < nat::N_ROUTERS ; $j++ ) {
			if ( $i != $j ) {
				printf $f "\t%s%s%s%s%s {\n", nat::RI_PREFIX,
				  nat::NAME_SEPARATOR, $routers[$i], nat::NAME_SEPARATOR,
				  $routers[$j];
				printf $f "\t\tinstance-type vrf;\n";
				printf $f "\t\tvrf-table-label;\n";
				printf $f "\t\tvrf-target %s%s;\n", nat::VRF_TARGET_PREFIX,
				  $vrf_target;
				if ( $i == $r ) {

					#add routes to the pic
					printf $f "\t\trouting-options {\n";
					printf $f "\t\t\tstatic {\n";
					printf $f "\t\t\t\troute 0.0.0.0/0 next-hop [%s];\n",
					  $spics_inside[$r];
					printf $f "\t\t\t}\n";
					printf $f "\t\t}\n";
				}
				if ( $j == $r ) {

#this router acts as backup, add backup routes to service pics, set preference accordingly
					printf $f "\t\trouting-options {\n";
					printf $f "\t\t\tstatic {\n";
					printf $f "\t\t\t\troute 0.0.0.0/0 {\n";
					printf $f "\t\t\t\t\tnext-hop [%s];\n", $spics_inside[$r];
					printf $f "\t\t\t\t\tno-readvertise;\n";
					printf $f "\t\t\t\t\tpreference %d;\n",
					  nat::BACKUP_ROUTE_PREFERENCE;
					printf $f "\t\t\t\t}\n";
					printf $f "\t\t\t}\n";
					printf $f "\t\t}\n";
				}
				printf $f "\t}\n";
				$vrf_target++;
			}
		}
	}

	#generate an instance for backup route injection
	printf $f "\t%s%s%s%s%s {\n", nat::RI_PREFIX, nat::NAME_SEPARATOR,
	  $routers[$r], nat::NAME_SEPARATOR, nat::VRF_BACKUP_SUFFIX;
	printf $f "\t\tinstance-type vrf;\n";
	printf $f "\t\tvrf-import %s;\n",     nat::VRF_POLICY_NULL_IMPORT;
	printf $f "\t\tvrf-export %s%s%s;\n", nat::VRF_POLICY_PREFIX,
	  nat::NAME_SEPARATOR, $routers[$r];

	#add routes to the pic
	printf $f "\t\trouting-options {\n";
	printf $f "\t\t\tstatic {\n";
	printf $f "\t\t\t\troute 0.0.0.0/0 next-hop [%s];\n", $spics_inside[$r];
	printf $f "\t\t\t}\n";
	printf $f "\t\t}\n";
	printf $f "\t}\n";

	#end of routing-instances
	printf $f "}\n";
}

sub gen_filters {
	my $r                      = shift;
	my $f                      = shift;
	my $nterms                 = 2**nat::MASK_BITS;
	my @subscriber_pools_array = split / /, $subscriber_pools;

	#spray filter
	printf $f "firewall {\n";
	printf $f "\t%sfilter %s{\n", nat::CONFIG_PREFIX, nat::SPRAY_FILTER_NAME;

	#filter for inside traffic
	# printf $f "\t\tterm accept-non-rfc1918-sources {\n", $t;
	# printf $f "\t\t\tfrom {\n";
	# printf $f "\t\t\t\tsource-address 0/0;\n";
	# printf $f "\t\t\t\tsource-address 10/8 except;\n";
	# printf $f "\t\t\t\tsource-address 192.168/16 except;\n";
	# printf $f "\t\t\t\tsource-address 172.16/12 except;\n";
	# printf $f "\t\t\t}\n";
	# printf $f "\t\t\tthen {\n";
	# printf $f "\t\t\t\taccept;\n";
	# printf $f "\t\t\t}\n";
	# printf $f "\t\t}\n";

	printf $f "\t\tterm accept-translated {\n", $t;
	printf $f "\t\t\tfrom {\n";
	printf $f "\t\t\t\tsource-prefix-list %s;\n", nat::POOL_PREFIX_LIST_NAME;
	printf $f "\t\t\t}\n";
	printf $f "\t\t\tthen {\n";
	printf $f "\t\t\t\taccept;\n";
	printf $f "\t\t\t\tcount %s;\n", nat::COUNT_TRANSLATED;
	printf $f "\t\t\t}\n";
	printf $f "\t\t}\n";

	#allow non-subscriber traffic skip NAT processing
	printf $f "\t\tterm accept-non-subscribers {\n", $t;
	printf $f "\t\t\tfrom {\n";
	printf $f "\t\t\t\tsource-address 0/0;\n";
	foreach my $pool (@subscriber_pools_array) {
		printf $f "\t\t\t\tsource-address %s except;\n", $pool;
	}
	printf $f "\t\t\t}\n";
	printf $f "\t\t\tthen {\n";
	printf $f "\t\t\t\taccept;\n";
	printf $f "\t\t\t\tcount %s;\n", nat::COUNT_NON_SUBSCRIBERS;
	printf $f "\t\t\t}\n";
	printf $f "\t\t}\n";

	for ( my $t = 0 ; $t < $nterms ; $t++ ) {
		my $r1;
		my $r2;
		my $segment;
		my $c;
		$c = $nterms / nat::N_ROUTERS;

		#find out the segment
		$segment =
		  int( $t * ( nat::N_ROUTERS - 1 ) * nat::N_ROUTERS / $nterms );
		$r1 = int( $segment / ( nat::N_ROUTERS - 1 ) );
		$r2 = ( $segment % ( nat::N_ROUTERS - 1 ) + $r1 + 1 ) % nat::N_ROUTERS;
		printf $f "\t\tterm t%02d {\n", $t;
		printf $f "\t\t\tfrom {\n";
		printf $f "\t\t\t\tsource-address 0.0.0.%d/0.0.0.%d;\n", $t,
		  $nterms - 1;
		printf $f "\t\t\t}\n";
		printf $f "\t\t\tthen {\n";
		printf $f "\t\t\t\trouting-instance %s%s%s%s%s;\n", nat::RI_PREFIX,
		  nat::NAME_SEPARATOR, $routers[$r1], nat::NAME_SEPARATOR,
		  $routers[$r2];
		printf $f "\t\t\t\tcount %s%03d;\n", nat::SPRAY_FILTER_COUNTER_PREFIX,
		  $t;
		printf $f "\t\t\t}\n";
		printf $f "\t\t}\n";
	}
	printf $f "\t}\n";    # end filter
	printf $f "}\n";
}

sub gen_policies {
	my $r = shift;
	my $f = shift;
	my $i;

	# RIB policy
	printf $f "policy-options {\n";

	# RIB import policy
	printf $f "\t%spolicy-statement %s {\n", nat::CONFIG_PREFIX,
	  nat::RIB_IMPORT_POLICY;
	printf $f "\t\tterm allow-default {\n";
	printf $f "\t\t\tfrom {\n";
	printf $f "\t\t\t\troute-filter 0.0.0.0/0 exact;\n";
	printf $f "\t\t\t}\n";
	printf $f "\t\t\tthen accept;\n";
	printf $f "\t\t}\n";
	printf $f "\t\tterm default {\n";
	printf $f "\t\t\tthen reject;\n";
	printf $f "\t\t}\n";
	printf $f "\t}\n";

	# Policy that rejects all routes
	printf $f "\t%spolicy-statement %s {\n", nat::CONFIG_PREFIX,
	  nat::VRF_POLICY_NULL_IMPORT;
	printf $f "\t\tterm default {\n";
	printf $f "\t\t\tthen reject;\n";
	printf $f "\t\t}\n";
	printf $f "\t}\n";

	# VRF export policy for backup routes
	printf $f "\t%spolicy-statement %s%s%s {\n", nat::CONFIG_PREFIX,
	  nat::VRF_POLICY_PREFIX, nat::NAME_SEPARATOR, $routers[$r];
	printf $f "\t\tthen {\n";
	printf $f "\t\t\tcommunity add %s%s%s;\n", nat::COMMUNITY_PREFIX,
	  nat::NAME_SEPARATOR, $routers[$r];
	printf $f "\t\t\tmy-preference %d;\n", nat::BACKUP_my_PREFERENCE;
	printf $f "\t\t\taccept;\n";
	printf $f "\t\t}\n";
	printf $f "\t}\n";

	# Community
	printf $f "\t%scommunity %s%s%s members [ ", nat::CONFIG_PREFIX,
	  nat::COMMUNITY_PREFIX, nat::NAME_SEPARATOR, $routers[$r];
	for ( $i = 0 ; $i < nat::N_ROUTERS - 1 ; $i++ ) {
		my $group;
		my $offset;
		$group = ( $r + $i + 1 ) % nat::N_ROUTERS;

		if ( $group > $r ) { $offset = $r; }
		else { $offset = $r - 1; }

		printf $f "%s%d ", nat::VRF_TARGET_PREFIX,
		  $group * ( nat::N_ROUTERS - 1 ) + $offset + nat::VRF_TARGET_FIRST;
	}
	printf $f "];\n";
	printf $f "}\n";
}
