from __future__ import annotations

import uuid

import great_expectations as gx
import pandas as pd


def run_expectations(
    df: pd.DataFrame,
    expectations: list,
    suite_name: str | None = None,
):
    """
    Validates *df* against the given list of GX Expectation objects.

    Uses a fully ephemeral context so no files are written to disk and
    nothing leaks between calls.  Returns a GX ValidationResult.
    """
    if suite_name is None:
        suite_name = f"suite_{uuid.uuid4().hex[:8]}"

    ctx = gx.get_context(mode="ephemeral")

    source = ctx.data_sources.add_pandas("_source")
    asset = source.add_dataframe_asset("_asset")
    batch_def = asset.add_batch_definition_whole_dataframe("_batch")

    suite = ctx.suites.add(gx.ExpectationSuite(name=suite_name))
    for exp in expectations:
        suite.add_expectation(exp)

    validation = ctx.validation_definitions.add(
        gx.ValidationDefinition(
            name="_validation",
            data=batch_def,
            suite=suite,
        )
    )

    return validation.run(batch_parameters={"dataframe": df})
