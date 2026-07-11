export type ModelKind = "openai" | "anthropic" | "openai-compatible";

export type ModelForm = {
  configId: string;
  name: string;
  kind: ModelKind;
  baseUrl: string;
  model: string;
  contextWindow: number;
  deviceId: string;
  apiKey: string;
  isDefault: boolean;
};

export type KeyMetadata = {
  keyLastFour: string;
  keyFingerprint: string;
};

export function modelMetadata(form: ModelForm, key: KeyMetadata) {
  return {
    id: form.configId,
    name: form.name.trim(),
    kind: form.kind,
    baseUrl: form.baseUrl.trim(),
    model: form.model.trim(),
    contextWindow: form.contextWindow,
    deviceId: form.deviceId,
    isDefault: form.isDefault,
    keyLastFour: key.keyLastFour,
    keyFingerprint: key.keyFingerprint,
  };
}
