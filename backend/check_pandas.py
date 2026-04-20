import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def ip_to_int(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return int(ip_obj)
        if ip_obj.version == 6:
            return int(ip_obj) % (2**63 - 1)
    except Exception:
        return 0
    return 0


def prot_to_int(prot) -> int:
    text = "" if prot is None or (isinstance(prot, float) and np.isnan(prot)) else str(prot)
    asc = [ord(c) for c in text]
    return int(sum(asc))


class DdosModel(nn.Module):
    def __init__(self, input_size: int):
        super().__init__()
        self.layer1 = nn.Linear(input_size, 16)
        self.dropout = nn.Dropout(0.5)
        self.layer2 = nn.Linear(16, 8)
        self.output = nn.Linear(8, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = torch.relu(self.layer1(x))
        x = self.dropout(x)
        x = torch.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.sigmoid(self.output(x))
        return x


DEFAULT_DROP = {"target", "Dest IP", "Source IP", "Dest Port", "Source Port"}


def preprocess_network_df(df: pd.DataFrame) -> pd.DataFrame:
    """Apply the same encodings used during training when those columns exist."""
    out = df.copy()
    if "Dest IP" in out.columns:
        out["Dest IP"] = out["Dest IP"].apply(ip_to_int).astype("int64")
    if "Highest Layer" in out.columns:
        out["Highest Layer"] = out["Highest Layer"].apply(prot_to_int)
    if "Transport Layer" in out.columns:
        out["Transport Layer"] = out["Transport Layer"].apply(prot_to_int)
    return out


def select_feature_columns(
    df: pd.DataFrame, feature_columns: Optional[Sequence[str]] = None
) -> Tuple[pd.DataFrame, List[str]]:
    """
    If feature_columns is set, use exactly those columns (in order).
    Otherwise use all columns except the usual label / IP / port fields.
    """
    if feature_columns:
        cols = [c.strip() for c in feature_columns if str(c).strip()]
        missing = set(cols) - set(df.columns)
        if missing:
            raise ValueError(f"Unknown columns in CSV: {sorted(missing)}")
        return df[cols].copy(), cols

    drop_present = [c for c in DEFAULT_DROP if c in df.columns]
    remaining = [c for c in df.columns if c not in set(drop_present)]
    if not remaining:
        raise ValueError(
            "No feature columns left after dropping target/IP/port columns; "
            "pass feature_columns explicitly."
        )
    return df[remaining].copy(), remaining


def dataframe_to_numeric_tensor(features: pd.DataFrame) -> torch.Tensor:
    """Coerce every column to float32 and return shape (n_rows, n_features)."""
    numeric = features.copy()
    for c in numeric.columns:
        numeric[c] = pd.to_numeric(numeric[c], errors="coerce").fillna(0.0)
    arr = numeric.to_numpy(dtype=np.float32, copy=False)
    return torch.from_numpy(arr)


def tensor_for_model_evaluation(
    features: torch.Tensor, apply_dropout_noise: bool = False
) -> torch.Tensor:
    """
    Standardize features to zero mean / unit variance (same idea as training)
    and return a float32 tensor ready for the model.

    Training used fit on train split; at inference we fit on the uploaded batch
    unless you persist a scaler from training.
    """
    if features.numel() == 0:
        raise ValueError("Empty feature tensor; nothing to evaluate.")
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features.detach().cpu().numpy())
    tensor = torch.from_numpy(scaled.astype(np.float32))
    if apply_dropout_noise:
        import Data_cleaner as dc

        tensor = dc.csv_Tensor.noisemaker(tensor)
    return tensor


def load_model_for_input_dim(weights_path: Path, input_dim: int) -> DdosModel:
    if not weights_path.is_file():
        raise FileNotFoundError(
            f"Model weights not found at {weights_path}. Train the model first "
            "(run check_pandas.py as a script) to create ddos_model.pth."
        )
    model = DdosModel(input_dim)
    try:
        state = torch.load(
            weights_path, map_location=torch.device("cpu"), weights_only=True
        )
    except TypeError:
        state = torch.load(weights_path, map_location=torch.device("cpu"))
    model.load_state_dict(state)
    model.eval()
    return model


def evaluate_model_on_tensor(model: DdosModel, x: torch.Tensor) -> torch.Tensor:
    """Return sigmoid probabilities, shape (n_rows, 1)."""
    with torch.no_grad():
        return model(x)


def infer_malware_from_dataframe(
    df: pd.DataFrame,
    weights_path: Path,
    feature_columns: Optional[Sequence[str]] = None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    End-to-end: preprocess -> column selection -> tensor -> scale -> model -> labels.
    """
    processed = preprocess_network_df(df)
    feature_df, used_columns = select_feature_columns(processed, feature_columns)
    raw_tensor = dataframe_to_numeric_tensor(feature_df)
    model_tensor = tensor_for_model_evaluation(raw_tensor, apply_dropout_noise=False)
    model = load_model_for_input_dim(weights_path, model_tensor.shape[1])
    probs = evaluate_model_on_tensor(model, model_tensor).squeeze(-1)
    prob_list = probs.detach().cpu().tolist()
    labels = ["Malware" if p > threshold else "Not Malware" for p in prob_list]
    return {
        "feature_columns_used": used_columns,
        "rows": len(labels),
        "input_shape": list(model_tensor.shape),
        "probabilities": prob_list,
        "labels": labels,
        "malware_count": sum(1 for lb in labels if lb == "Malware"),
    }


if __name__ == "__main__":
    import matplotlib.pyplot as plt
    import Data_cleaner as dc

    file = pd.read_csv(r"C:\Users\1dayk\Downloads\archive\DDoS_dataset.csv")
    print(file.isnull().sum())
    print(file.describe())
    print(file.head())
    print(file.columns)
    file["Dest IP"] = file["Dest IP"].apply(ip_to_int).astype("int64")
    file["Highest Layer"] = file["Highest Layer"].apply(prot_to_int)
    file["Transport Layer"] = file["Transport Layer"].apply(prot_to_int)
    print(file)
    print(file.dtypes)

    y = torch.tensor(file["target"].values, dtype=torch.float32)

    file = file.drop(columns=["target", "Dest IP", "Source IP", "Dest Port", "Source Port"])
    x = torch.tensor(file.values, dtype=torch.float32)

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()

    x_train = scaler.fit_transform(x_train)
    x_test = scaler.transform(x_test)

    x_train_tensor = torch.tensor(x_train, dtype=torch.float32)
    x_test_tensor = torch.tensor(x_test, dtype=torch.float32)

    y_train_tensor = y_train.reshape(-1, 1)
    y_test_tensor = y_test.reshape(-1, 1)

    x_train_tensor = dc.csv_Tensor.noisemaker(x_train_tensor)

    model = DdosModel(x_train_tensor.shape[1])

    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-4)
    losses = []
    epochs = 800

    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        outputs = model(x_train_tensor)
        loss = criterion(outputs, y_train_tensor)
        loss.backward()
        optimizer.step()
        losses.append(loss.item())
        if (epoch + 1) % 200 == 0:
            model.eval()
            with torch.no_grad():
                test_outputs = model(x_test_tensor)
                test_loss = criterion(test_outputs, y_test_tensor)
            model.train()
            print(
                f"Epoch [{epoch+1}/{epochs}], Train Loss: {loss.item():.4f}, "
                f"Test Loss: {test_loss.item():.4f}"
            )

    plt.plot(losses)
    plt.show()

    model.eval()

    with torch.no_grad():
        outputs = model(x_test_tensor)
        predicted = outputs.round()

    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )

    accuracy = accuracy_score(y_test, predicted)
    precision = precision_score(y_test, predicted, zero_division=0)
    recall = recall_score(y_test, predicted, zero_division=0)
    f1 = f1_score(y_test, predicted, zero_division=0)
    cm = confusion_matrix(y_test, predicted)

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")

    out_path = Path(__file__).resolve().parent / "ddos_model.pth"
    torch.save(model.state_dict(), out_path)
    print(f"Model successfully saved to {out_path}")
