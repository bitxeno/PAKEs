use base64::{engine::general_purpose, Engine as _};
use hex_literal::hex;
use sha2::Sha512;
use srp::client::SrpClient;
use srp::groups::G_3072;

#[test]
fn apple_lockdown_cu_verification() {
    let username = b"Pair-Setup";
    let password = b"185364";
    let salt = hex!("121a596b6510b68d3dd4ec55c23d9dd1");

    // Server Public Key (B) - 384 bytes
    let b_pub = hex!(
        "b9352a021ebf589dfa1228be968b5c5a024afe40efc8e1ab835b79a19bc53f82"
        "a900b4eeb2001b79a9b351babb99afb2f5506c3ef5b2cb08957b4e88d6b2cd4b"
        "a9e1e14fe95e2e268f1d0ebee6ddab8f2516e9e2026dc13a31a19f5ee3530ba8"
        "085ce56fc4fb0f9fc3e11504f246bd1cb2defcabf21bcc57abdc018a66f0ea14"
        "c6d92f391fe652c2572e68a0ca0e20b03b33eb15accc00265d3f380d9cae97ab"
        "4b9a4f04a2f758a1a0c616acf97ce678118262bf71046f270d526450c1ceedbd"
        "17de74b59dad103a8bd2fc7234fecd55505490bdff3b3ca80d96597ada599c7d"
        "098d60e02ace5f344a3849fd38840e2501b5c9b5056159e9b421dda226920f58"
        "418594c48826b779b6c3b0c3265082edeadaa9c9b9c49ab42ea331a4afda843c"
        "aa5a95290dfde1aaa7e6832fb5d280f169023924ca16f1d47ae936d00382696e"
        "3124413dce4dbf30f9389cbb7836770ea2ae23166b92033076b48e2fcd3f1b09"
        "40971c9dfa442d670b83a5d9025fa0efa5be8b340d60a91334f12b84af098a55"
    );

    // Client Private Key (a) - 32 bytes
    let a_priv = hex!("d06480cff66228a77a7a9fdfe3a8ac216a0d77b7584f793d1ee1048bd971b184");

    // Expected Client Public Key (A) - 384 bytes
    let expected_a_pub = hex!(
        "5eb191ef5e5114d69d88fa0f41258cfc78dfa147ec507fc45c3873663156a86d"
        "0caa5379ac6f7921a328884f1499d2fd43d21305de46ed8d2c800e34c20f8761"
        "3d50ef22621971ea5b67dd72d15b7f4ace93275f5c74005c0fc535edcc7e155a"
        "7dd286b7a7fbefa5943fff019f04b10d32ff597c6928a092f5628c40f13890de"
        "b46055158526c5985dc7c240751bafed1683b9cd5275079b0a290d5b788970c2"
        "c7c8a93b4f176c4d13c64f79c3e45ea7d1f4ab7879b6dcdec088342ad3abfbf3"
        "60b677b9a97cf663d934414c76aa37c12420161a875703f24c5bb147eda4d846"
        "e609af52802da5c84d3a1dfc567c4d305d10225959cb1394c3ab3f69329da72a"
        "21d95ffffa1543ced42b657310b1fa97bb6babbc807de7dde189797a605f7240"
        "6d8bd7d7865803f1db64158fe941d8ae60d202ff0ae5046fbe190091338e5288"
        "7c789299036b8706f958a3d1175ee05834be8dcd3d972101c01f8a38bc011048"
        "4c8fa04dade0b96fd1b56c3adef3da4bbb8924e32e0dc8be2cb49cf8b9f00129"
    );

    // Expected Proof (M1) - 64 bytes
    let expected_m1 = hex!(
        "6a2fa0638e7a423d539b5dc5ba122fa31dc7598a270e4b5b452d8b3e8ea32d59"
        "3943eb793cefac2f55f132b009e01018f5a99ddc7292102ce7071eed8c8be486"
    );

    // Expected Session Key (K) - 64 bytes
    let expected_k = hex!(
        "0988d53283900546ede9206f0673a70a017ddcb400ed8fe2a9616c23d43fa79c"
        "e043c77fbb76ae8c366d9ee86096291eb76b681a06d4b06c6174f3f14676c651"
    );

    let client = SrpClient::<Sha512>::new(&G_3072);

    // Verify A calculation
    let a_pub = client.compute_public_ephemeral(&a_priv);
    assert_eq!(
        a_pub, expected_a_pub,
        "Computed A does not match expected A"
    );

    // Process reply
    let verifier = client
        .process_reply(&a_priv, username, password, &salt, &b_pub)
        .expect("Handshake failed");

    // Verify Session Key (K)
    assert_eq!(
        verifier.key(),
        expected_k,
        "Computed Session Key (K) does not match expected K"
    );

    println!(
        "Computed M1 Base64: {}",
        general_purpose::STANDARD.encode(verifier.proof())
    );
    println!(
        "Expected M1 Base64: {}",
        general_purpose::STANDARD.encode(expected_m1)
    );

    // Verify Proof (M1)
    assert_eq!(
        verifier.proof(),
        expected_m1,
        "Computed Proof (M1) does not match expected M1"
    );
}
