use std::{fs, io::Write, iter, net::TcpStream, sync::Arc};

use rustls::crypto::Identity;
use rustls::{pki_types::ServerName, ClientConfig, Connection, RootCertStore};
use webpki_root_certs::TLS_SERVER_ROOT_CERTS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let (_, ignored) = roots.add_parsable_certificates(TLS_SERVER_ROOT_CERTS.iter().cloned());
    assert_eq!(ignored, 0, "{ignored} root certificates were ignored");
    let config = Arc::new(
        ClientConfig::builder(Arc::new(rustls_ring::DEFAULT_PROVIDER.clone()))
            .with_root_certificates(roots)
            .with_no_client_auth()?,
    );

    for &host in HOSTS {
        let server_name = ServerName::try_from(host.to_owned())?;
        let mut conn = config.connect(server_name).build()?;
        let mut sock = TcpStream::connect((host, 443))?;

        eprintln!("connecting to {host}...");
        while conn.is_handshaking() {
            if conn.wants_write() {
                conn.write_tls(&mut sock)?;
            }

            if conn.wants_read() {
                if conn.read_tls(&mut sock)? == 0 {
                    break;
                }
                conn.process_new_packets()?;
            }
        }

        conn.writer()
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())?;
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }

        let Some(Identity::X509(certs)) = conn.peer_identity() else {
            eprintln!("no certificates received for {host}");
            continue;
        };

        for (i, der) in iter::once(&certs.end_entity)
            .chain(certs.intermediates.iter())
            .enumerate()
        {
            let host_name = host.replace('.', "_");
            let fname = format!(
                "{}/src/tests/verification_real_world/{host_name}_valid_{}.crt",
                env!("CARGO_MANIFEST_DIR"),
                i + 1
            );
            fs::write(&fname, der.as_ref())?;
            eprintln!("wrote certificate to {fname}");
        }
    }

    Ok(())
}

// We use two different CAs for better coverage and...
const HOSTS: &[&str] = &[
    // This host is using EC-based certificates for coverage.
    "letsencrypt.org",
    // This host is using RSA-based certificates for coverage.
    "aws.amazon.com",
];
