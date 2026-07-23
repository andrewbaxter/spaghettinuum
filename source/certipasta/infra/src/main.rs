use {
    std::{
        env,
        fs::{
            self,
            },
        path::PathBuf,
    },
    certifier::{
        ServerConfig,
        ENV_SERVER_CONFIG,
        ENV_ROTATE_CONFIG,
        RotateConfig,
    },
    terrars::{
        primvec,
        BuildStack,
        BuildVariable,
        tf_trim_prefix,
        tf_substr,
        tf_trim_suffix,
        tf_base64decode,
    },
    terrars_andrewbaxter_dinker::{
        BuildImage,
        BuildImageFilesEl,
        BuildProviderDinker,
    },
    terrars_andrewbaxter_localrun::{
        BuildDataRun,
        BuildProviderLocalrun,
    },
    terrars_dnsimple_dnsimple::{
        BuildProviderDnsimple,
        BuildZoneRecord,
    },
    terrars_hashicorp_google::{
        BuildProviderGoogle,
        BuildProjectService,
        BuildCloudRunService,
        BuildCloudRunServiceTemplateEl,
        BuildCloudRunServiceTemplateElSpecEl,
        BuildCloudRunServiceTemplateElSpecElContainersEl,
        BuildCloudRunDomainMapping,
        BuildArtifactRegistryRepository,
        BuildServiceAccount,
        BuildServiceAccountKey,
        BuildCloudRunDomainMappingSpecEl,
        BuildCloudRunServiceTemplateElSpecElContainersElEnvEl,
        BuildCloudRunServiceTemplateElSpecElContainersElPortsEl,
        BuildKmsKeyRing,
        BuildKmsCryptoKey,
        BuildKmsCryptoKeyIamBinding,
        BuildStorageBucket,
        BuildStorageBucketIamBinding,
        BuildArtifactRegistryRepositoryIamBinding,
        BuildCloudRunDomainMappingMetadataEl,
        BuildKmsCryptoKeyVersionTemplateEl,
        BuildCloudRunServiceIamBinding,
    },
    terrars_hectorj_googlesiteverification::{
        BuildProviderGooglesiteverification,
        BuildDataDnsToken,
        BuildDns,
    },
    terrars_integrations_github::{
        BuildDataActionsPublicKey,
        BuildActionsSecret,
        BuildProviderGithub,
        BuildActionsVariable,
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
    let target_root = PathBuf::from(&env::var("CARGO_TARGET_DIR").unwrap());

    // Bootstrap/seed host
    {
        let deploy_root = root.join("stage");
        let tf_root = deploy_root.join("tf");
        fs::create_dir_all(&tf_root).unwrap();
        let stack = &mut BuildStack {}.build();

        // Some data
        let domain = "certipasta.isandrew.com";
        let domain_zone = "isandrew.com";
        let zone_rel_domain = domain.strip_suffix(domain_zone).unwrap().strip_suffix(".").unwrap();
        let location = "us-central1";
        let project = "certipasta";

        // Input vars
        let dnsimple_token = &BuildVariable { tf_id: "dnsimple_token".into() }.build(stack).set_sensitive(true);
        let github_token = &BuildVariable { tf_id: "github_token".into() }.build(stack).set_sensitive(true);
        let google_creds = &BuildVariable { tf_id: "google_creds".into() }.build(stack).set_sensitive(true);

        // Auth
        BuildProviderLocalrun {}.build(stack);
        BuildProviderDinker {}
            .build(stack)
            .set_cache_dir(deploy_root.join("dinker_cache").to_string_lossy().to_string());
        BuildProviderDnsimple {}.build(stack).set_account("139852").set_token(dnsimple_token);
        BuildProviderGoogle {}.build(stack).set_credentials(&*google_creds).set_project(project);
        BuildProviderGooglesiteverification {}.build(stack).set_credentials(&*google_creds);
        BuildProviderGithub {}.build(stack).set_token(github_token);

        // Project generally
        let enable_gcp_resource_api = BuildProjectService {
            tf_id: "zOSJATSNC".into(),
            service: "cloudresourcemanager.googleapis.com".into(),
        }.build(stack);
        let enable_gcp_iam_api = BuildProjectService {
            tf_id: "z81XDKWRI".into(),
            service: "iam.googleapis.com".into(),
        }.build(stack);

        // Cross-resource service accounts
        let server_service_account = BuildServiceAccount {
            tf_id: "zDJBX4RQB".into(),
            account_id: "server".into(),
        }.build(stack).depends_on(&enable_gcp_iam_api);
        let pipeline_service_account = BuildServiceAccount {
            tf_id: "zLM19FMHZ".into(),
            account_id: "pipelines".into(),
        }.build(stack).depends_on(&enable_gcp_iam_api);
        let pipeline_creds = BuildServiceAccountKey {
            tf_id: "zZGDIU2PD".into(),
            service_account_id: pipeline_service_account.id().into(),
        }.build(stack);

        // Key management
        let enable_gcp_bucket_api = BuildProjectService {
            tf_id: "z40KL9DPR".into(),
            service: "storage-component.googleapis.com".into(),
        }.build(stack).depends_on(&enable_gcp_resource_api);
        let certs_bucket = BuildStorageBucket {
            tf_id: "zLR7WMBE6".into(),
            location: location.into(),
            name: "zlr7wmbe6".into(),
        }.build(stack).depends_on(&enable_gcp_bucket_api);
        BuildStorageBucketIamBinding {
            tf_id: "zW63DEV5N".into(),
            bucket: certs_bucket.name().into(),
            members: vec![format!("serviceAccount:{}", pipeline_service_account.email()).into()].into(),
            role: "roles/storage.objectUser".into(),
        }.build(stack);
        BuildStorageBucketIamBinding {
            tf_id: "zNAAQLQ2V".into(),
            bucket: certs_bucket.name().into(),
            members: vec!["allUsers".into()].into(),
            role: "roles/storage.objectViewer".into(),
        }.build(stack);
        let logs_bucket = BuildStorageBucket {
            tf_id: "zLOGBUCKET1".into(),
            location: location.into(),
            name: "zlogbucket1".into(),
        }.build(stack).depends_on(&enable_gcp_bucket_api);
        BuildStorageBucketIamBinding {
            tf_id: "zLOGBUCKETW".into(),
            bucket: logs_bucket.name().into(),
            members: vec![format!("serviceAccount:{}", pipeline_service_account.email()).into()].into(),
            role: "roles/storage.objectUser".into(),
        }.build(stack);
        BuildStorageBucketIamBinding {
            tf_id: "zLOGBUCKETR".into(),
            bucket: logs_bucket.name().into(),
            members: vec!["allUsers".into()].into(),
            role: "roles/storage.objectViewer".into(),
        }.build(stack);
        let enable_gcp_keys_api = BuildProjectService {
            tf_id: "zBXWMHWWS".into(),
            service: "cloudkms.googleapis.com".into(),
        }.build(stack).depends_on(&enable_gcp_resource_api);
        let gks_key_ring = BuildKmsKeyRing {
            tf_id: "zTFLQCXZW".into(),
            location: location.into(),
            name: "certipasta_keyring".into(),
        }.build(stack).depends_on(&enable_gcp_keys_api);
        let gks_key =
            BuildKmsCryptoKey {
                tf_id: "z0T0G1499".into(),
                name: "certifier".into(),
                key_ring: gks_key_ring.id().into(),
            }
                .build(stack)
                .set_purpose("ASYMMETRIC_SIGN")
                .set_version_template(
                    vec![BuildKmsCryptoKeyVersionTemplateEl { algorithm: "EC_SIGN_P256_SHA256".into() }.build()],
                )
                .set_skip_initial_version_creation(true);
        BuildKmsCryptoKeyIamBinding {
            tf_id: "z5NHEL3EF".into(),
            crypto_key_id: gks_key.id().into(),
            members: vec![format!("serviceAccount:{}", server_service_account.email()).into()].into(),
            role: "roles/cloudkms.signerVerifier".into(),
        }.build(stack);
        BuildKmsCryptoKeyIamBinding {
            tf_id: "zQD0E4KH8".into(),
            crypto_key_id: gks_key.id().into(),
            members: vec![format!("serviceAccount:{}", pipeline_service_account.email()).into()].into(),
            role: "roles/cloudkms.admin".into(),
        }.build(stack);
        BuildKmsCryptoKeyIamBinding {
            tf_id: "zNHY4OSV1".into(),
            crypto_key_id: gks_key.id().into(),
            members: vec![format!("serviceAccount:{}", pipeline_service_account.email()).into()].into(),
            role: "roles/cloudkms.cryptoOperator".into(),
        }.build(stack);

        // Image building and cloud run
        let enable_artifact_registry_api = BuildProjectService {
            tf_id: "z8PU7S2ED".into(),
            service: "artifactregistry.googleapis.com".into(),
        }.build(stack);
        let gcr = BuildArtifactRegistryRepository {
            tf_id: "z1WXC166V".into(),
            repository_id: "images".into(),
            format: "DOCKER".into(),
        }.build(stack).depends_on(&enable_artifact_registry_api).set_location(location);
        let gcr_deploy_service_account = BuildServiceAccount {
            tf_id: "zZLVUGIMT".into(),
            account_id: "deploy-push".into(),
        }.build(stack).depends_on(&enable_gcp_iam_api);
        BuildArtifactRegistryRepositoryIamBinding {
            tf_id: "zKR00B6ET".into(),
            members: vec![format!("serviceAccount:{}", gcr_deploy_service_account.email()).into()].into(),
            repository: gcr.id().into(),
            role: "roles/artifactregistry.writer".into(),
        }.build(stack);
        let gcr_deploy_creds = BuildServiceAccountKey {
            tf_id: "zEQ49BS1H".into(),
            service_account_id: gcr_deploy_service_account.id().into(),
        }.build(stack);
        let rust_dir = root.join("software/certifier");
        let rust =
            BuildDataRun {
                tf_id: "z22WPM6IT".into(),
                command: primvec![
                    "cargo",
                    "build",
                    "--no-default-features",
                    "--target=x86_64-unknown-linux-musl",
                    "--bin=certifier-server",
                    "--release"
                ].into(),
            }
                .build(stack)
                .set_working_dir(rust_dir.to_str().unwrap())
                .set_outputs(
                    primvec![target_root.join("x86_64-unknown-linux-musl/release/certifier-server").to_str().unwrap()],
                );
        let bin_server = rust.outputs().get(0);
        let bin_server_hash = rust.output_hashes().get(0);
        let image_app =
            BuildImage {
                tf_id: "zN7CYROBV".into(),
                dest: format!(
                    "docker://{}-docker.pkg.dev/{}/{}/server:{}-{}",
                    location,
                    project,
                    gcr.repository_id(),
                    tf_substr(stack, bin_server_hash, 0, 8),
                    "{short_hash}"
                ).into(),
                files: vec![BuildImageFilesEl { source: bin_server.into() }.build().set_mode("0755")],
            }
                .build(stack)
                .set_arch("amd64")
                .set_os("linux")
                .set_cmd(primvec!["/certifier-server"])
                .set_dest_user("_json_key_base64")
                .set_dest_password(gcr_deploy_creds.private_key());

        // App
        let enable_gcp_run_api = BuildProjectService {
            tf_id: "zJNXGIVC1".into(),
            service: "run.googleapis.com".into(),
        }.build(stack);
        let run_service = BuildCloudRunService {
            tf_id: "zMEW8YTTM".into(),
            location: location.into(),
            name: "certifier".into(),
        }.build(stack).depends_on(&enable_gcp_run_api).set_template(vec![
            //. .
            BuildCloudRunServiceTemplateEl {}.build().set_spec(vec![
                //. .
                BuildCloudRunServiceTemplateElSpecEl {}
                    .build()
                    .set_service_account_name(pipeline_service_account.email())
                    .set_containers(vec![
                        //. .
                        BuildCloudRunServiceTemplateElSpecElContainersEl {
                            image: tf_trim_prefix(stack, image_app.rendered_dest(), "docker://".to_string()).into(),
                        }
                            .build()
                            .set_env(vec![
                                //. BuildCloudRunServiceTemplateElSpecElContainersElEnvEl {}
                                //.     .build()
                                //.     .set_name("RUST_BACKTRACE")
                                //.     .set_value("1"),
                                BuildCloudRunServiceTemplateElSpecElContainersElEnvEl {}
                                    .build()
                                    .set_name(ENV_SERVER_CONFIG)
                                    .set_value(
                                        serde_json::to_string(
                                            &ServerConfig {
                                                key_gcpid: gks_key.id().to_string(),
                                                cert_bucket: certs_bucket.name().to_string(),
                                                log_bucket: logs_bucket.name().to_string(),
                                            },
                                        ).unwrap(),
                                    )
                            ])
                            .set_ports(
                                vec![
                                    BuildCloudRunServiceTemplateElSpecElContainersElPortsEl {}
                                        .build()
                                        .set_container_port(80f64)
                                ],
                            )
                    ])
            ])
        ]);
        BuildCloudRunServiceIamBinding {
            tf_id: "zL7SSH9N3".into(),
            members: vec!["allUsers".into()].into(),
            role: "roles/run.invoker".into(),
            service: run_service.name().into(),
        }.build(stack).set_location(location);

        // DNS
        let enable_gcp_site_verification_api = BuildProjectService {
            tf_id: "zBGB9G06U".into(),
            service: "siteverification.googleapis.com".into(),
        }.build(stack).depends_on(&enable_gcp_resource_api);
        let verification_token = BuildDataDnsToken {
            tf_id: "zZLN6CEBB".into(),
            domain: domain.into(),
        }.build(stack).depends_on(&enable_gcp_site_verification_api);
        let verification_record = BuildZoneRecord {
            tf_id: "zLE4Y9FXI".into(),
            name: tf_trim_suffix(
                stack,
                verification_token.record_name(),
                format!(".{}", domain_zone.to_string()),
            ).into(),
            zone_name: domain_zone.into(),
            type_: verification_token.record_type().into(),
            value: verification_token.record_value().into(),
        }.build(stack).set_ttl(180f64);
        let verification = BuildDns {
            tf_id: "zVPWCDDMV".into(),
            domain: domain.into(),
            token: verification_token.record_value().into(),
        }.build(stack).depends_on(&verification_record);
        let run_domain_mapping =
            BuildCloudRunDomainMapping {
                tf_id: "z2FYU3BNT".into(),
                location: location.into(),
                name: domain.into(),
            }
                .build(stack)
                .depends_on(&verification)
                .set_spec(vec![BuildCloudRunDomainMappingSpecEl { route_name: run_service.name().into() }.build()])
                .set_metadata(vec![BuildCloudRunDomainMappingMetadataEl { namespace: project.into() }.build()]);
        for i in 0 .. 8 {
            // Always 8? Not documented
            let mapping_rec = run_domain_mapping.status().get(0).resource_records().get(i);
            BuildZoneRecord {
                tf_id: format!("zX1MU5YOQ-{}", i).into(),
                name: zone_rel_domain.into(),
                zone_name: domain_zone.into(),
                type_: mapping_rec.type_().into(),
                value: mapping_rec.rrdata().into(),
            }.build(stack).set_ttl(180f64);
        }

        // Github secrets
        let gh_repo = "certipasta";
        let gh_key = BuildDataActionsPublicKey {
            tf_id: "zQ2EPSYFQ".into(),
            repository: gh_repo.into(),
        }.build(stack);
        BuildActionsSecret {
            tf_id: "zC8XOM7EC".into(),
            repository: gh_repo.into(),
            secret_name: "GOOGLE_APPLICATION_CREDENTIALS".into(),
        }
            .build(stack)
            .depends_on(&gh_key)
            .set_plaintext_value(tf_base64decode(stack, pipeline_creds.private_key()));
        BuildActionsVariable {
            tf_id: "zBHQB8EZ9".into(),
            repository: gh_repo.into(),
            variable_name: ENV_ROTATE_CONFIG.into(),
            value: serde_json::to_string(&RotateConfig {
                key_gcpid: gks_key.id().to_string(),
                bucket: certs_bucket.name().into(),
            }).unwrap().into(),
        }.build(stack);

        // Save the stack file
        fs::write(tf_root.join("stack.tf.json"), stack.serialize(&tf_root.join("state.json")).unwrap()).unwrap();
    }
}
