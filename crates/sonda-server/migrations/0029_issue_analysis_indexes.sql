-- Issues by the analyses they point at. Each of these is a foreign key, so
-- without an index, deleting one analysis (retention, a pull request's
-- after 30 days) scanned every issue three times: about 340 ms an analysis
-- with a million issues, under the branch's lock. They also serve an
-- analysis's page, which lists the issues it found and fixed.
CREATE INDEX issues_first_analysis ON issues (first_analysis_id);
CREATE INDEX issues_last_analysis ON issues (last_analysis_id);
CREATE INDEX issues_fixed_analysis ON issues (fixed_analysis_id)
    WHERE fixed_analysis_id IS NOT NULL;
