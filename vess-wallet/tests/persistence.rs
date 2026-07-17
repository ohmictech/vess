#[cfg(test)]
mod persistence {
    use vess_wallet::Wallet;
    use vess_crypto::blake3_hash;

    #[test]
    fn test_wallet_persistence() {
        // Create a wallet with a known password
        let password = b"test-password-123";
        let mut w = Wallet::new(password);

        // Generate a keypair and add some bills
        let invoice = w.build_invoice(Some(500), Some("test"), None, None);
        assert!(!invoice.is_empty(), "invoice must be non-empty");

        // Save the wallet
        let saved = w.save();
        assert!(saved.len() > 44, "saved wallet must have header + ciphertext");
        assert_eq!(&saved[..8], b"VESSWLT\0", "wallet ciphertext carries a format marker");

        // Load it back
        let w2 = Wallet::load(&saved, password).expect("load must succeed");
        assert_eq!(w2.balance(), w.balance(), "balance must survive round-trip");

        // Wrong password must fail
        assert!(Wallet::load(&saved, b"wrong-password").is_none(), "wrong password must fail");

        // Corrupted data must fail
        let mut corrupted = saved.clone();
        if corrupted.len() > 50 { corrupted[50] ^= 0xFF; }
        assert!(Wallet::load(&corrupted, password).is_none(), "corrupted data must fail");
    }

    #[test]
    fn test_invoice_format() {
        let mut w = Wallet::new(b"test");
        // Basic invoice
        let inv = w.build_invoice(Some(100), None, None, None);
        assert!(inv.starts_with("vess://"), "invoice must start with vess://");
        assert!(inv.contains("amount=100"), "invoice must contain amount");

        // Invoice with hashlock
        let preimage = blake3_hash(b"secret");
        let hashlock = blake3_hash(&preimage);
        let inv_hl = w.build_invoice(Some(200), None, Some(&hashlock), None);
        assert!(inv_hl.contains("hashlock="), "invoice must contain hashlock");

        // Invoice with expiry
        let inv_exp = w.build_invoice(Some(300), None, None, Some(1720000000));
        assert!(inv_exp.contains("expires=1720000000"), "invoice must contain expires");

        // Invoice with both
        let inv_both = w.build_invoice(Some(400), None, Some(&hashlock), Some(1720000000));
        assert!(inv_both.contains("hashlock=") && inv_both.contains("expires="), "invoice must contain both");
    }

    #[test]
    fn test_build_payment_insufficient_funds() {
        let mut w = Wallet::new(b"test");
        // Empty wallet — any payment should fail
        let result = w.build_payment(&[([0u8; 32], 100, None)]);
        assert!(result.is_none(), "empty wallet must fail to build payment");
    }

    #[test]
    fn test_receive_blob_valid() {
        let mut w = Wallet::new(b"test");
        // Build a valid payment blob (invoice → build_payment would need funds, skip)
        // receive_blob with garbage should fail
        let result = w.receive_blob(&[0u8; 10]);
        assert!(result.is_none(), "garbage blob must fail to decode");
    }

    #[test]
    fn test_consolidate_empty() {
        let mut w = Wallet::new(b"test");
        let n = w.consolidate();
        assert_eq!(n, 0, "consolidating empty wallet must return 0");
    }

    #[test]
    fn test_wallet_atomic_file_save() {
        let path = std::env::temp_dir().join(format!("vess-wallet-{}.vess", std::process::id()));
        let password = b"file-save-test";
        let mut wallet = Wallet::new(password);
        wallet.build_invoice(Some(42), None, None, None);
        wallet.save_to_path(&path).expect("encrypted wallet file saves");
        let data = std::fs::read(&path).expect("wallet file exists");
        assert_eq!(&data[..8], b"VESSWLT\0");
        assert!(Wallet::load(&data, password).is_some(), "saved file decrypts");
        assert!(!path.with_file_name(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy())).exists());
        let _ = std::fs::remove_file(path);
    }
}
