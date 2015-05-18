#!/usr/bin/perl 
use POSIX;
use nat;

for ( my $r = 0 ; $r < nat::N_ROUTERS ; $r++ ) {
	my $f;
	my @routers     = nat::get_routers;
	my $router_name = $routers[$r];
	open( $f, '>', "$router_name-nat-svcs.cfg" );
	gen_intf_config( $r, $f );
	gen_services( $r, $f );
	gen_policies( $r, $f );
	close($f);
}

sub gen_intf_config {
	my $r     = shift;
	my $f     = shift;
	my @spics = nat::get_service_pics;
	printf $f "interfaces {\n";

	my @intf = split / /, $spics[$r];

	for ( my $i = 0 ; $i < @intf ; $i++ ) {
		printf $f "\t%s%s {\n", nat::CONFIG_PREFIX, $intf[$i];
		printf $f "\t\tunit %d{\n", nat::L3_UNIT_INSIDE;
		printf $f "\t\t\tfamily inet;\n";
		printf $f "\t\t\tservice-domain inside;\n";
		printf $f "\t\t}\n";
		printf $f "\t\tunit %d{\n", nat::L3_UNIT_OUTSIDE;
		printf $f "\t\t\tfamily inet;\n";
		printf $f "\t\t\tservice-domain outside;\n";
		printf $f "\t\t}\n";
		printf $f "\t}\n";
	}
	printf $f "}\n";
}

sub gen_services {
	my $r     = shift;
	my $f     = shift;
	my @spics = nat::get_service_pics();

	my @intf = split / /, $spics[$r];

	my @pool_names;

	printf $f "%sservices {\n", nat::CONFIG_PREFIX;
	printf $f "\tnat {\n";

	#generate pools
	my @pools = nat::get_external_pools();

	my @router_nat_pool = split / /, $pools[$r];

	for ( my $i = 0 ; $i < @router_nat_pool ; $i++ ) {

		$router_nat_pool[$i] =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;

		$pool_names[$i] = "$1_$2_$3_$4";

		printf $f "\t\tpool %s {\n",     $pool_names[$i];
		printf $f "\t\t\taddress %s;\n", $router_nat_pool[$i];
		printf $f "\t\t\tport automatic;\n";
		printf $f "\t\t}\n";    # pool
	}

	#generate NAT rules
	for ( my $i = 0 ; $i < @router_nat_pool ; $i++ ) {
		printf $f "\t\trule %s%d {\n", nat::NAT_RULE_PREFIX, $i;
		printf $f "\t\t\tmatch-direction input;\n";
		printf $f "\t\t\tterm t1 {\n";
		printf $f "\t\t\t\tthen {\n";
		printf $f "\t\t\t\t\ttranslated {\n";

		printf $f "\t\t\t\t\t\tsource-pool %s;\n", $pool_names[$i];
		printf $f "\t\t\t\t\t\ttranslation-type source dynamic;\n";
		printf $f "\t\t\t\t\t}\n";
		printf $f "\t\t\t\t}\n";
		printf $f "\t\t\t}\n";
		printf $f "\t\t}\n";    # nat rule
	}
	printf $f "\t}\n";          #nat

	#generate service sets
	for ( my $i = 0 ; $i < @router_nat_pool ; $i++ ) {
		printf $f "\tservice-set %s%d {\n", nat::SERVICE_SET_PREFIX, $i;
		printf $f "\t\tnat-rules %s%d;\n",  nat::NAT_RULE_PREFIX,    $i;
		printf $f "\t\tnext-hop-service {\n";

		printf $f "\t\t\tinside-service-interface %s.%d;\n", $intf[$i],
		  nat::L3_UNIT_INSIDE;
		printf $f "\t\t\toutside-service-interface %s.%d;\n", $intf[$i],
		  nat::L3_UNIT_OUTSIDE;

		printf $f "\t\t}\n";
		printf $f "\t}\n";    # service set
	}
	printf $f "}\n";
}

sub gen_policies {
	my $r     = shift;
	my $f     = shift;
	my @pools = nat::get_external_pools();

	my @router_nat_pool = split / /, $pools[$r];

	printf $f "policy-options {\n";

	printf $f "\t%sprefix-list %s {\n", nat::CONFIG_PREFIX,
	  nat::POOL_PREFIX_LIST_NAME;

	for ( my $i = 0 ; $i < @router_nat_pool ; $i++ ) {
		printf $f "\t\t%s;\n", $router_nat_pool[$i];
	}
	printf $f "\t}\n";                        #prefix-list
	printf $f "}\n";
}
