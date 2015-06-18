.PHONY = nightly

help:
	$(info -- Targets -- )
	$(info )
	$(info nightly  -   run cargo with nightly configuration, set ARGS to something like 'build'. rustc must be set to nightly)
	$(info _____________Note that for using stable, you can use cargo directly)
	$(info )

nightly:
	cargo $(ARGS) --no-default-features --features=nightly