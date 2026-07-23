use {
    std::{
        env,
        fs::{
            self,
            read,
        },
        path::PathBuf,
    },
    terrars::{
        primvec,
        BuildStack,
        BuildVariable,
    },
    terrars_andrewbaxter_dinker::BuildProviderDinker,
    terrars_andrewbaxter_localrun::{
        BuildDataRun,
        BuildProviderLocalrun,
    },
    terrars_dnsimple_dnsimple::{
        BuildProviderDnsimple,
        BuildZoneRecord,
    },
    terrars_hashicorp_google::{
        BuildComputeAddress,
        BuildComputeDisk,
        BuildComputeFirewall,
        BuildComputeFirewallAllowEl,
        BuildComputeImage,
        BuildComputeImageRawDiskEl,
        BuildComputeInstance,
        BuildComputeInstanceAttachedDiskEl,
        BuildComputeInstanceBootDiskEl,
        BuildComputeInstanceBootDiskElInitializeParamsEl,
        BuildComputeInstanceNetworkInterfaceEl,
        BuildComputeInstanceNetworkInterfaceElAccessConfigEl,
        BuildComputeInstanceNetworkInterfaceElIpv6AccessConfigEl,
        BuildComputeNetwork,
        BuildComputeSubnetwork,
        BuildProjectService,
        BuildProviderGoogle,
        BuildStorageBucket,
        BuildStorageBucketLifecycleRuleEl,
        BuildStorageBucketLifecycleRuleElActionEl,
        BuildStorageBucketLifecycleRuleElConditionEl,
        BuildStorageBucketObject,
    },
};

fn main() {
    let root =
        PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

    // Bootstrap/seed host
    {
        let build_root = root.join("stage");
        let tf_root = build_root.join("tf");
        fs::create_dir_all(&tf_root).unwrap();
        let stack = &mut BuildStack {}.build();

        // Some data
        let domain = "antipasta.isandrew.com";
        let domain_zone = "isandrew.com";
        let zone_rel_domain = domain.strip_suffix(domain_zone).unwrap().strip_suffix(".").unwrap();
        let location = "us-west1";
        let zone = format!("{}-b", location);
        let project = "antipasta";

        // Input vars
        let dnsimple_token = &BuildVariable { tf_id: "dnsimple_token".into() }.build(stack).set_sensitive(true);
        let google_creds = String::from_utf8(read(tf_root.join("google_creds.json")).unwrap()).unwrap();

        //. let dot_acme_kid =
        //.     &BuildVariable { tf_id: "dot_acme_kid".into() }.build::<String>(stack).set_sensitive(true);
        //. let dot_acme_hmac_b64 =
        //.     &BuildVariable { tf_id: "dot_acme_hmac_b64".into() }.build::<String>(stack).set_sensitive(true);
        // Auth
        BuildProviderLocalrun {}.build(stack);
        BuildProviderDinker {}
            .build(stack)
            .set_cache_dir(build_root.join("dinker_cache").to_string_lossy().to_string());
        BuildProviderDnsimple {}.build(stack).set_account("139852").set_token(dnsimple_token);
        BuildProviderGoogle {}.build(stack).set_credentials(&google_creds).set_project(project);

        // Project generally
        let enable_gcp_resource_api = BuildProjectService {
            tf_id: "zOSJATSNC".into(),
            service: "cloudresourcemanager.googleapis.com".into(),
        }.build(stack);
        let enable_gcp_compute_api = BuildProjectService {
            tf_id: "zKRG8NOSE".into(),
            service: "compute.googleapis.com".into(),
        }.build(stack).depends_on(&enable_gcp_resource_api);
        let enable_gcp_bucket_api = BuildProjectService {
            tf_id: "z40KL9DPR".into(),
            service: "storage-component.googleapis.com".into(),
        }.build(stack).depends_on(&enable_gcp_resource_api);

        // IP addresses
        let app_net = BuildComputeNetwork {
            tf_id: "zZAIHPVEZ".into(),
            name: "antipasta-net".into(),
        }.build(stack).set_auto_create_subnetworks(false);
        let app_ipv4 = BuildComputeAddress {
            tf_id: "zISYNBZ01".into(),
            name: "antipasta-ipv4".into(),
        }.build(stack).set_region(location).set_ip_version("IPV4");
        let app_subnet = {
            let id = "zG3AO34C4";
            BuildComputeSubnetwork {
                tf_id: id.into(),
                ip_cidr_range: "10.0.0.0/24".into(),
                name: id.to_ascii_lowercase().into(),
                network: app_net.id().into(),
            }.build(stack).set_region(location).set_stack_type("IPV4_IPV6").set_ipv6_access_type("EXTERNAL")
        };
        let app_ipv6 =
            BuildComputeAddress {
                tf_id: "zNE934NJW".into(),
                name: "antipasta-ipv6".into(),
            }
                .build(stack)
                .set_prevent_destroy(true)
                .set_region(location)
                .set_subnetwork(&app_subnet.id())
                .set_ip_version("IPV6")
                .set_ipv6_endpoint_type("VM");

        // Image building and cloud run
        let rust_out = build_root.join("nix/image");
        let rust =
            BuildDataRun {
                tf_id: "z22WPM6IT".into(),
                command: {
                    primvec![
                        "nix",
                        "--extra-experimental-features",
                        "nix-command",
                        "build",
                        "--print-build-logs",
                        "-f",
                        "os/image.nix",
                        "config.system.build.gcpimage",
                        "-o",
                        &rust_out.to_string_lossy().to_string(),
                        "--argstr",
                        "identityJson",
                        &String::from_utf8(read(tf_root.join("identity.json")).unwrap()).unwrap()
                    ]
                }.into(),
            }
                .build(stack)
                .set_working_dir(root.to_str().unwrap())
                .set_outputs(primvec![rust_out.join("compressed-image.tar.gz").to_str().unwrap()]);
        let bin_server = rust.outputs().get(0);
        let image_bucket = {
            let id = "zZK6VXCW0";
            BuildStorageBucket {
                tf_id: id.into(),
                location: location.into(),
                name: id.to_ascii_lowercase().into(),
            }
                .build(stack)
                .depends_on(&enable_gcp_bucket_api)
                .set_lifecycle_rule(
                    vec![
                        BuildStorageBucketLifecycleRuleEl {}
                            .build()
                            .set_condition(
                                vec![BuildStorageBucketLifecycleRuleElConditionEl {}.build().set_age(1f64)],
                            )
                            .set_action(
                                vec![BuildStorageBucketLifecycleRuleElActionEl { type_: "Delete".into() }.build()],
                            )
                    ],
                )
        };
        let image_obj = BuildStorageBucketObject {
            tf_id: "zJO4Y4B3C".into(),
            bucket: image_bucket.id().into(),
            name: "image.tar.gz".into(),
        }.build(stack).set_source(bin_server);
        let image_image =
            BuildComputeImage {
                tf_id: "zM2CTU28Y".into(),
                name: "antipasta".into(),
            }
                .build(stack)
                .depends_on(&enable_gcp_compute_api)
                .set_raw_disk(vec![BuildComputeImageRawDiskEl { source: image_obj.self_link().into() }.build()]);

        // VM
        let app_disk = {
            let id = "z9HHV4OAF";
            BuildComputeDisk {
                tf_id: id.into(),
                name: id.to_ascii_lowercase().into(),
            }.build(stack).set_zone(&zone).set_size(1f64)
        };
        BuildComputeInstance {
            tf_id: "zCY4N15TS".into(),
            machine_type: "e2-micro".into(),
            name: "antipasta-inst".into(),
        }
            .build(stack)
            .set_zone(&zone)
            .set_boot_disk(
                vec![
                    BuildComputeInstanceBootDiskEl {}
                        .build()
                        .set_initialize_params(
                            vec![
                                BuildComputeInstanceBootDiskElInitializeParamsEl {}.build().set_image(image_image.id())
                            ],
                        )
                ],
            )
            .set_attached_disk(
                vec![BuildComputeInstanceAttachedDiskEl { source: app_disk.self_link().into() }.build()],
            )
            .set_network_interface(
                vec![
                    BuildComputeInstanceNetworkInterfaceEl {}
                        .build()
                        .set_subnetwork(app_subnet.id())
                        .set_stack_type("IPV4_IPV6")
                        .set_access_config(
                            vec![
                                BuildComputeInstanceNetworkInterfaceElAccessConfigEl {}
                                    .build()
                                    .set_nat_ip(app_ipv4.address())
                            ],
                        )
                        .set_ipv6_access_config(
                            vec![
                                BuildComputeInstanceNetworkInterfaceElIpv6AccessConfigEl {
                                    network_tier: "PREMIUM".into(),
                                }
                                    .build()
                                    .set_external_ipv6(app_ipv6.address())
                                    .set_external_ipv6_prefix_length(app_ipv6.prefix_length().to_string())
                            ],
                        )
                ],
            );
        {
            let id = "zR63LXYPT";
            BuildComputeFirewall {
                tf_id: id.into(),
                network: app_net.id().into(),
                name: id.to_ascii_lowercase().into(),
            }
                .build(stack)
                .set_priority(1000f64)
                .set_direction("INGRESS")
                .set_source_ranges(primvec!["::/0"])
                .set_allow(vec![BuildComputeFirewallAllowEl { protocol: "all".into() }.build()]);
        }
        {
            let id = "zM1M3110X";
            BuildComputeFirewall {
                tf_id: id.into(),
                network: app_net.id().into(),
                name: id.to_ascii_lowercase().into(),
            }
                .build(stack)
                .set_priority(1000f64)
                .set_direction("INGRESS")
                .set_source_ranges(primvec!["0.0.0.0/0"])
                .set_allow(vec![BuildComputeFirewallAllowEl { protocol: "all".into() }.build()]);
        }

        // DNS
        BuildZoneRecord {
            tf_id: "zACTDIDY7".into(),
            name: zone_rel_domain.into(),
            zone_name: domain_zone.into(),
            type_: "A".into(),
            value: app_ipv4.address().into(),
        }.build(stack).set_ttl(180f64);
        BuildZoneRecord {
            tf_id: "zYSUV4RZT".into(),
            name: zone_rel_domain.into(),
            zone_name: domain_zone.into(),
            type_: "AAAA".into(),
            value: app_ipv6.address().into(),
        }.build(stack).set_ttl(180f64);

        // Save the stack file
        fs::write(tf_root.join("stack.tf.json"), stack.serialize(&tf_root.join("state.json")).unwrap()).unwrap();
    }
}
