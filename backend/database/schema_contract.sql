-- Fail closed when a persistent development database does not exactly match
-- this release's committed schema. Update the signature only from a database
-- freshly created from schema.sql.
DO $schema_contract$
DECLARE
    expected_tables CONSTANT TEXT[] := ARRAY[
        'assets',
        'campaign_artifact_cursors',
        'campaign_artifacts',
        'campaign_container_counters',
        'campaign_contexts',
        'campaign_crash_groups',
        'campaign_progression_actions',
        'campaigns',
        'coverage_checkpoints',
        'coverage_evidence',
        'findings',
        'projects',
        'tasks'
    ];
    expected_schema_comment CONSTANT TEXT := 'bigeye-schema:release-1';
    expected_signature CONSTANT TEXT := 'ee18f07bb3e3b61555741da0a083b439';
    actual_tables TEXT[];
    actual_schema_comment TEXT;
    actual_signature TEXT;
BEGIN
    SELECT array_agg(tablename ORDER BY tablename)
      INTO actual_tables
      FROM pg_tables
     WHERE schemaname = 'public';

    IF actual_tables IS DISTINCT FROM expected_tables THEN
        RAISE EXCEPTION
            'schema catalog does not match: expected tables %, found %',
            expected_tables,
            actual_tables;
    END IF;

    SELECT obj_description('public'::regnamespace, 'pg_namespace')
      INTO actual_schema_comment;
    IF actual_schema_comment IS DISTINCT FROM expected_schema_comment THEN
        RAISE EXCEPTION
            'schema catalog does not match: expected schema marker %, found %',
            expected_schema_comment,
            actual_schema_comment;
    END IF;

    WITH catalog_items AS (
        SELECT format('relation|%s|%s', relation.relname, relation.relkind) AS item
          FROM pg_class AS relation
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relkind IN ('r', 'p', 'S', 'v', 'm')
        UNION ALL
        SELECT format(
                   'column|%s|%s|%s|%s|%s|%s|%s',
                   table_name,
                   column_name,
                   udt_name,
                   is_nullable,
                   is_identity,
                   COALESCE(identity_generation, ''),
                   COALESCE(column_default, '')
               )
          FROM information_schema.columns
         WHERE table_schema = 'public'
        UNION ALL
        SELECT format(
                   'constraint|%s|%s|%s|%s',
                   relation.relname,
                   constraint_record.conname,
                   constraint_record.contype,
                   pg_get_constraintdef(constraint_record.oid, true)
               )
          FROM pg_constraint AS constraint_record
          JOIN pg_class AS relation ON relation.oid = constraint_record.conrelid
          JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
        UNION ALL
        SELECT format('index|%s|%s|%s', tablename, indexname, indexdef)
          FROM pg_indexes
         WHERE schemaname = 'public'
    )
    SELECT md5(string_agg(item, E'\n' ORDER BY item))
      INTO actual_signature
      FROM catalog_items;

    IF actual_signature IS DISTINCT FROM expected_signature THEN
        RAISE EXCEPTION
            'schema catalog does not match: expected signature %, found %',
            expected_signature,
            actual_signature;
    END IF;
END
$schema_contract$;
