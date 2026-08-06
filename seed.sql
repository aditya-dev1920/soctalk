DO $$
DECLARE
    org_id UUID;
BEGIN
    -- 1. Upsert organization by mssp_id and capture its actual ID
    INSERT INTO public.organizations (id, mssp_id, mssp_name, install_id, install_label, slug, created_at, updated_at) 
    VALUES ('11111111-1111-4111-a111-111111111111', 'dec0de00-0000-4000-8000-000000000001', 'Default MSSP Org', 'dec0de00-0000-4000-8000-000000000002', 'Default EC2 Install', 'default-mssp-org', NOW(), NOW()) 
    ON CONFLICT (mssp_id) DO UPDATE SET 
        mssp_name = EXCLUDED.mssp_name,
        install_id = EXCLUDED.install_id,
        install_label = EXCLUDED.install_label,
        slug = EXCLUDED.slug,
        updated_at = NOW();

    SELECT id INTO org_id FROM public.organizations WHERE mssp_id = 'dec0de00-0000-4000-8000-000000000001';

    -- 2. Ensure Tenants exist using the resolved organization_id
    INSERT INTO public.tenants (id, slug, display_name, organization_id) 
    VALUES 
      ('3ce40a6d-cdce-446c-a2d9-244b1356e493', 'customer-a', 'Customer A', org_id),
      ('4de50b7e-dedf-557d-b3ea-355c2467f5a4', 'customer-b', 'Customer B', org_id)
    ON CONFLICT (slug) DO UPDATE SET organization_id = EXCLUDED.organization_id;

    -- 3. Clean up stale dependent password credentials and test users to avoid ID mismatches
    DELETE FROM public.password_credentials WHERE user_id IN (
        SELECT id FROM public.users WHERE email IN (
            'admin@devlab.local', 'dev@devlab.local', 'admin_global@dev.local', 
            'xcubeops@gmail.com', 'tenant-admin@customer.a', 'analyst@customer.a', 
            'tenant-admin@customer.b', 'analyst@customer.b'
        )
    );

    DELETE FROM public.users WHERE email IN (
        'admin@devlab.local', 'dev@devlab.local', 'admin_global@dev.local', 
        'xcubeops@gmail.com', 'tenant-admin@customer.a', 'analyst@customer.a', 
        'tenant-admin@customer.b', 'analyst@customer.b'
    );

    -- 4. Insert All 8 Users fresh with exact target IDs
    INSERT INTO public.users (id, email, display_name, user_type, role, tenant_id, active)
    VALUES 
      ('a0000000-0000-0000-0000-000000000001', 'admin@devlab.local', 'Primary Admin', 'mssp', 'mssp_admin', NULL, true),
      ('a0000000-0000-0000-0000-000000000002', 'dev@devlab.local', 'Developer Admin', 'mssp', 'mssp_admin', NULL, true),
      ('a0000000-0000-0000-0000-000000000003', 'admin_global@dev.local', 'Global Admin', 'mssp', 'mssp_admin', NULL, true),
      ('a0000000-0000-0000-0000-000000000004', 'xcubeops@gmail.com', 'XCubeOps Admin', 'tenant', 'tenant_admin', '3ce40a6d-cdce-446c-a2d9-244b1356e493', true),
      ('a0000000-0000-0000-0000-000000000005', 'tenant-admin@customer.a', 'Customer A Admin', 'tenant', 'tenant_admin', '3ce40a6d-cdce-446c-a2d9-244b1356e493', true),
      ('a0000000-0000-0000-0000-000000000006', 'analyst@customer.a', 'Customer A Analyst', 'tenant', 'tenant_analyst', '3ce40a6d-cdce-446c-a2d9-244b1356e493', true),
      ('a0000000-0000-0000-0000-000000000007', 'tenant-admin@customer.b', 'Customer B Admin', 'tenant', 'tenant_admin', '4de50b7e-dedf-557d-b3ea-355c2467f5a4', true),
      ('a0000000-0000-0000-0000-000000000008', 'analyst@customer.b', 'Customer B Analyst', 'tenant', 'tenant_analyst', '4de50b7e-dedf-557d-b3ea-355c2467f5a4', true);

    -- 5. Assign Passwords mapping directly to those IDs
    INSERT INTO public.password_credentials (user_id, password_hash, consecutive_failures, locked_until, must_change)
    VALUES 
      ('a0000000-0000-0000-0000-000000000001', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000002', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000003', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000004', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000005', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000006', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000007', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false),
      ('a0000000-0000-0000-0000-000000000008', '$2b$10$EixZaYVK1QQkMnx8HYW3ooUvE56IG7urXO5r5A.hUXePZea4V.KLS', 0, NULL, false);
END $$;
