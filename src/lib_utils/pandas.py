import pandas as pd


# Define the reference and comparison dataframes
def df_diff(df_ref, df_cmp, cols, on="sku"):
    df_merged = pd.merge(
        df_ref[[on, *cols]], df_cmp[[on, *cols]], on=on, suffixes=("_ref", "_cmp")
    )
    df_diff = df_merged.query(" or ".join([f"{col}_ref != {col}_cmp" for col in cols]))
    return df_ref[df_ref[on].isin(df_diff[on].unique())]
