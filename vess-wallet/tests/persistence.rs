#[cfg(test)]
mod persistence {
    use vess_wallet::Wallet;

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
}
