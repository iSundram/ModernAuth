-- Drop tables in reverse order of creation to handle foreign key dependencies

DROP TABLE IF EXISTS email_tracking_pixels;
DROP TABLE IF EXISTS email_branding_advanced;
DROP TABLE IF EXISTS email_ab_test_results;
DROP TABLE IF EXISTS email_ab_tests;
