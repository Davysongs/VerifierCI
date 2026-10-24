-- 002_immutability_triggers.sql
-- Migration 002: Add immutability triggers for patch panels and auxiliary entities.

-- Patch Panels
CREATE TRIGGER patch_panels_no_core_update BEFORE UPDATE OF panel_key, panel_id, version, split, membership_digest, sampling_policy, parent_panel_key ON patch_panels
BEGIN SELECT RAISE(ABORT, 'immutable entity patch_panels cannot be updated'); END;

CREATE TRIGGER patch_panels_sealed_no_update BEFORE UPDATE ON patch_panels
WHEN OLD.sealed_at IS NOT NULL
  AND (
    NEW.panel_key != OLD.panel_key
    OR NEW.panel_id != OLD.panel_id
    OR NEW.version != OLD.version
    OR NEW.split != OLD.split
    OR NEW.membership_digest != OLD.membership_digest
    OR NEW.sampling_policy != OLD.sampling_policy
    OR NEW.parent_panel_key IS NOT OLD.parent_panel_key
    OR NEW.sealed_at IS NOT OLD.sealed_at
    OR NEW.exposed_at IS NOT OLD.exposed_at
    OR NEW.development_used_at IS NOT OLD.development_used_at
  )
BEGIN SELECT RAISE(ABORT, 'immutable entity patch_panels cannot be updated'); END;

CREATE TRIGGER patch_panels_no_delete BEFORE DELETE ON patch_panels
BEGIN SELECT RAISE(ABORT, 'immutable entity patch_panels cannot be deleted'); END;

-- Exposure Events
CREATE TRIGGER exposure_events_no_update BEFORE UPDATE ON exposure_events
BEGIN SELECT RAISE(ABORT, 'immutable entity exposure_events cannot be updated'); END;
CREATE TRIGGER exposure_events_no_delete BEFORE DELETE ON exposure_events
BEGIN SELECT RAISE(ABORT, 'immutable entity exposure_events cannot be deleted'); END;

-- Analysis Plans
CREATE TRIGGER analysis_plans_no_update BEFORE UPDATE ON analysis_plans
BEGIN SELECT RAISE(ABORT, 'immutable entity analysis_plans cannot be updated'); END;
CREATE TRIGGER analysis_plans_no_delete BEFORE DELETE ON analysis_plans
BEGIN SELECT RAISE(ABORT, 'immutable entity analysis_plans cannot be deleted'); END;

-- Benchmark Versions
CREATE TRIGGER benchmark_versions_no_update BEFORE UPDATE ON benchmark_versions
BEGIN SELECT RAISE(ABORT, 'immutable entity benchmark_versions cannot be updated'); END;
CREATE TRIGGER benchmark_versions_no_delete BEFORE DELETE ON benchmark_versions
BEGIN SELECT RAISE(ABORT, 'immutable entity benchmark_versions cannot be deleted'); END;

-- Telemetry Events
CREATE TRIGGER telemetry_events_no_update BEFORE UPDATE ON telemetry_events
BEGIN SELECT RAISE(ABORT, 'immutable entity telemetry_events cannot be updated'); END;
CREATE TRIGGER telemetry_events_no_delete BEFORE DELETE ON telemetry_events
BEGIN SELECT RAISE(ABORT, 'immutable entity telemetry_events cannot be deleted'); END;

-- Worker Requests
CREATE TRIGGER worker_requests_no_update BEFORE UPDATE ON worker_requests
BEGIN SELECT RAISE(ABORT, 'immutable entity worker_requests cannot be updated'); END;
CREATE TRIGGER worker_requests_no_delete BEFORE DELETE ON worker_requests
BEGIN SELECT RAISE(ABORT, 'immutable entity worker_requests cannot be deleted'); END;

