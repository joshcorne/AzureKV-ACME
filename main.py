from acme import AcmeClient

if __name__ == "__main__":
    client = AcmeClient()
    account = client.register_account()
    print("Account details:", account)


    #TODO: WIP
    domains = []
    order, order_url = client.create_order(domains)

    challenges = client.get_challenges(order)

    for authz in challenges:
        http_chal = next(c for c in authz["challenges"] if c["type"] == "http-01")
        chal_info = client.get_http_challenge_info(http_chal)

        print(f"Place file at: /.well-known/acme-challenge/{chal_info['token']}")
        print(f"With content: {chal_info['key_auth']}")
        input("Press Enter once the challenge file is served...")

        client.trigger_challenge(chal_info['url'])
        client.wait_for_valid(chal_info['url'])

    cert_url = client.finalize_order(order, order_url, domains)
    cert_pem = client.download_certificate(cert_url)

    with open("certificate.pem", "w") as f:
        f.write(cert_pem)

    print("Certificate saved to certificate.pem")