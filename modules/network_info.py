from ipwhois import IPWhois

def get_network_details(ip):
    """Requests the IP address's network details (ASN, Owner, Country)"""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()

        extraction = {}

        # 1. Network hierarchy and identifiers
        extraction["net_name"] = results.get('network', {}).get('name')
        extraction["net_handle"] = results.get('network', {}).get('handle')
        extraction["cidr"] = results.get('network', {}).get('cidr')
        extraction["country"] = results.get('asn_country_code') or results.get('network', {}).get('country')

        # 2. Timeline
        events = results.get('network', {}).get('events') or []
        for event in events:
            action = event.get('action', 'unknown')
            date = event.get('timestamp')
            extraction[f"date_{action.replace(' ', '_')}"] = date

        # 3. Org data (Remarks)
        remarks = results.get('network', {}).get('remarks') or []
        if remarks and 'description' in remarks[0]:
            desc = remarks[0]['description']

            if isinstance(desc, list):
                extraction["organization"] = " | ".join(desc)
            else:
                extraction["organization"] = desc

        # 4. Entity data (Person/Organisation)
        abuse_emails = []
        tech_phones = []
        tech_names = []
        addresses = []

        objects = results.get('objects') or {}
        for handle, data in objects.items():
            roles = data.get('roles') or []
            contact = data.get('contact') or {}

            if contact.get('name'):
                tech_names.append(f"{contact.get('name')} ({', '.join(roles)})")

            # E-mails
            emails = contact.get('email') or []
            for e in emails:
                email_val = e.get('value')
                if 'abuse' in roles:
                    abuse_emails.append(email_val)

            # Phone Numbers
            phones = contact.get('phone') or []
            for p in phones:
                phone_val = p.get('value')
                if phone_val:
                    tech_phones.append(phone_val)

            # Address data
            address_list = contact.get('address') or []
            for addr in address_list:
                if addr.get('value'):
                    addresses.append(addr.get('value').replace('\n', ', '))

        extraction["abuse_contacts"] = ", ".join(list(set(abuse_emails))) or "N/A"
        extraction["tech_names"] = " | ".join(tech_names)
        extraction["tech_phones"] = ", ".join(list(set(tech_phones)))
        extraction["org_address"] = " | ".join(list(set(addresses)))

        # 5. GDPR / Redacted sign (if info is hidden)
        redacted = results.get('redacted') or []
        if redacted:
            extraction["gdpr_status"] = f"Data restriction enabled({len(redacted)} field hidden)"

        return extraction

    except Exception as e:
        return {"error": f"Network error: {str(e)}"}