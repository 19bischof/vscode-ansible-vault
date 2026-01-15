import * as vscode from "vscode";
import {
  extractVaultId,
  findAnsibleCfgFile,
  findPassword,
  getConfigFileInWorkspace,
  getInlineTextType,
  getTextType,
  scanAnsibleCfg,
  verifyAnsibleDirectory,
} from "./util";
import { Vault } from "ansible-vault";

const logs = vscode.window.createOutputChannel("Ansible Vault");

class VaultedLineCodeLensProvider implements vscode.CodeLensProvider {
  provideCodeLenses(
    document: vscode.TextDocument,
    token: vscode.CancellationToken
  ): vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {
    const codeLenses: vscode.CodeLens[] = [];

    for (let line = 0; line < document.lineCount; line++) {
      const text = document.lineAt(line).text;

      // Check for !vault | or !vault |- or $ANSIBLE_VAULT indicators
      if (text.match(/!vault \|[-+]?/) || text.startsWith("$ANSIBLE_VAULT;")) {
        const range = new vscode.Range(line, 0, line, text.length);
        const copyAction = new vscode.CodeLens(range, {
          title: "📋 Copy",
          command: "extension.copyDecryptedVault",
          arguments: [document.uri, line],
        });
        codeLenses.push(copyAction);
        const decryptAction = new vscode.CodeLens(range, {
          title: "🔓 Decrypt",
          command: "extension.decryptVaultedLine",
          arguments: [document.uri, line, false],
        });
        codeLenses.push(decryptAction);
      }
    }

    return codeLenses;
  }

  resolveCodeLens(
    codeLens: vscode.CodeLens,
    token: vscode.CancellationToken
  ): vscode.CodeLens | Thenable<vscode.CodeLens> {
    return codeLens;
  }
}

// Helper function to get password for a vault ID
async function getPasswordForVault(
  documentUri: vscode.Uri
): Promise<{ vaultPass: { [key: string]: string } | false } | null> {
  const configFileInWorkspacePath = getConfigFileInWorkspace(logs, documentUri);
  let otherPath = findAnsibleCfgFile(logs, documentUri.fsPath, "ansible.cfg");

  if (otherPath !== undefined) {
    otherPath = verifyAnsibleDirectory(logs, documentUri, otherPath);
  }

  const [keyInCfg, vaultIds, vaultPass] = scanAnsibleCfg(
    logs,
    otherPath,
    configFileInWorkspacePath
  );

  return { vaultPass };
}

// Helper function to decrypt vault text
async function decryptVaultText(
  vaultText: string,
  documentUri: vscode.Uri
): Promise<string | undefined> {
  const vaultId = extractVaultId(vaultText);
  const passwordInfo = await getPasswordForVault(documentUri);
  
  if (!passwordInfo) {
    return undefined;
  }

  const { vaultPass } = passwordInfo;
  let pass: string = "";

  // Get password from ansible.cfg vault_identity_list
  if (vaultPass) {
    if (vaultPass[vaultId] !== undefined) {
      pass = findPassword(logs, documentUri.fsPath, vaultPass[vaultId]) || "";
    } else if (vaultPass["default"] !== undefined) {
      pass = findPassword(logs, documentUri.fsPath, vaultPass["default"]) || "";
    }
  }

  if (!pass) {
    return undefined;
  }

  const cleanedText = vaultText
    .replace(/!vault \|[-+]?\s*/, "")
    .trim()
    .replace(/[^\S\r\n]+/gm, "");

  const vault = new Vault({ password: pass });
  try {
    if (vaultId && vaultId !== "default" && vaultId !== "") {
      return (await vault.decrypt(cleanedText, vaultId)) as string;
    } else {
      return (await vault.decrypt(cleanedText, undefined)) as string;
    }
  } catch (error: any) {
    logs.appendLine(`❌ Hover decrypt failed: ${error.message}`);
    return undefined;
  }
}

// Extract the full vault block from a document starting at a given line
function extractVaultBlock(document: vscode.TextDocument, startLine: number): string {
  const text = document.getText();
  const lineOffset = document.offsetAt(new vscode.Position(startLine, 0));
  
  // Find the start of the vault (either !vault | or $ANSIBLE_VAULT)
  let vaultStart = text.indexOf("!vault |", lineOffset);
  if (vaultStart === -1 || vaultStart > lineOffset + 200) {
    // Try finding $ANSIBLE_VAULT directly
    vaultStart = text.indexOf("$ANSIBLE_VAULT;", lineOffset);
  }
  if (vaultStart === -1) {
    vaultStart = lineOffset;
  }

  // Find the end of the vault block
  const headerStart = text.indexOf("$ANSIBLE_VAULT;", vaultStart);
  if (headerStart === -1) {
    return "";
  }

  let vaultEnd = text.indexOf("\n", headerStart);
  if (vaultEnd === -1) {
    vaultEnd = text.length;
  }

  // Get the indentation of the hex content
  let indent = "";
  if (vaultEnd + 1 < text.length && text.charAt(vaultEnd + 1) === " ") {
    let i = 1;
    while (vaultEnd + i < text.length && text.charAt(vaultEnd + i) === " ") {
      indent += " ";
      i++;
    }
  }

  // Continue reading lines with the same indentation
  while (vaultEnd < text.length) {
    const nextLineStart = vaultEnd + 1;
    if (nextLineStart >= text.length) break;
    
    const nextLineIndent = text.slice(nextLineStart, nextLineStart + indent.length);
    if (nextLineIndent !== indent || indent === "") break;
    
    const nextNewline = text.indexOf("\n", nextLineStart);
    if (nextNewline === -1) {
      vaultEnd = text.length;
      break;
    }
    vaultEnd = nextNewline;
  }

  return text.substring(vaultStart, vaultEnd);
}

// Hover provider for showing decrypted values
class VaultHoverProvider implements vscode.HoverProvider {
  async provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    token: vscode.CancellationToken
  ): Promise<vscode.Hover | null> {
    const line = document.lineAt(position.line);
    const text = line.text;

    // Check if this line or nearby lines contain a vault
    if (!text.match(/!vault \|[-+]?/) && !text.includes("$ANSIBLE_VAULT;") && !text.match(/^[\s]+[0-9a-f]+$/)) {
      return null;
    }

    // Find the start of the vault block by going up
    let vaultStartLine = position.line;
    while (vaultStartLine > 0) {
      const lineText = document.lineAt(vaultStartLine).text;
      if (lineText.match(/!vault \|[-+]?/) || lineText.startsWith("$ANSIBLE_VAULT;")) {
        break;
      }
      if (!lineText.match(/^[\s]+[0-9a-f]+$/) && !lineText.includes("$ANSIBLE_VAULT;")) {
        // Not part of a vault block
        return null;
      }
      vaultStartLine--;
    }

    const vaultText = extractVaultBlock(document, vaultStartLine);
    if (!vaultText) {
      return null;
    }

    try {
      const decrypted = await decryptVaultText(vaultText, document.uri);
      if (decrypted) {
        const markdown = new vscode.MarkdownString();
        markdown.appendMarkdown(`**🔓 Decrypted Value:**\n\n`);
        markdown.appendCodeblock(decrypted, "text");
        markdown.isTrusted = true;
        return new vscode.Hover(markdown);
      }
    } catch (error: any) {
      logs.appendLine(`❌ Hover error: ${error.message}`);
    }

    return null;
  }
}

export function activate(context: vscode.ExtensionContext) {
  logs.appendLine(
    '🎉 Congratulations! Your extension "ansible-vault-vscode" is now active!'
  );

  // CodeLens Decrypt command - decrypts vault IN-PLACE (replaces with plaintext)
  const decryptCommand = vscode.commands.registerCommand(
    "extension.decryptVaultedLine",
    async (uri: vscode.Uri, line: number) => {
      logs.appendLine("🔓 CodeLens Decrypt: Starting in-place decryption");
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        return;
      }
      const document = await vscode.workspace.openTextDocument(uri);
      
      // Extract the vault block
      const vaultText = extractVaultBlock(document, line);
      if (!vaultText || getInlineTextType(vaultText) !== "encrypted") {
        vscode.window.showErrorMessage("No valid vault found at this location");
        return;
      }

      // Decrypt the vault
      const decrypted = await decryptVaultText(vaultText, uri);
      if (!decrypted) {
        vscode.window.showErrorMessage("Failed to decrypt vault");
        return;
      }

      // Find the range to replace (from !vault | to end of vault block)
      const lineAt = document.lineAt(line);
      const vaultMatch = lineAt.text.match(/^(\s*)(\w[\w_]*)\s*:\s*!vault/);
      if (!vaultMatch) {
        vscode.window.showErrorMessage("Could not parse YAML key");
        return;
      }

      const [, indent, key] = vaultMatch;
      
      // Find the end of the vault block
      let endLine = line + 1;
      const baseIndent = indent.length + 4; // Vault content is indented
      while (endLine < document.lineCount) {
        const checkLine = document.lineAt(endLine).text;
        // Check if line is part of vault (starts with spaces and is hex or $ANSIBLE_VAULT)
        if (checkLine.match(/^\s+([0-9a-f]+|\$ANSIBLE_VAULT)/)) {
          endLine++;
        } else {
          break;
        }
      }

      // Replace the entire vault with the decrypted value
      const startPos = new vscode.Position(line, 0);
      const endPos = new vscode.Position(endLine - 1, document.lineAt(endLine - 1).text.length);
      const range = new vscode.Range(startPos, endPos);

      await editor.edit((editBuilder) => {
        editBuilder.replace(range, `${indent}${key}: ${decrypted}`);
      });
      
      logs.appendLine(`✅ Decrypted in-place successfully`);
      vscode.window.showInformationMessage("✅ Vault decrypted!");
    }
  );

  // Smart YAML command: encrypt plaintext value OR copy decrypted vault to clipboard
  const inlineEncryptOrCopy = async () => {
    logs.appendLine("🔐 Starting smart YAML command.");
    
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return;
    }

    const document = editor.document;
    const position = editor.selection.active;
    const line = document.lineAt(position.line);
    const lineText = line.text;

    // Check if we're on or near a vault block
    let vaultBlock: string | null = null;
    let vaultStartLine = position.line;
    
    // Look for vault indicator on current line or above
    if (lineText.match(/!vault \|[-+]?/) || lineText.includes("$ANSIBLE_VAULT;") || lineText.match(/^\s+[0-9a-f]+$/)) {
      // Find the start of the vault block
      while (vaultStartLine > 0) {
        const checkLine = document.lineAt(vaultStartLine).text;
        if (checkLine.match(/!vault \|[-+]?/)) {
          break;
        }
        if (checkLine.match(/^\s*\w+.*:/) && !checkLine.includes("$ANSIBLE_VAULT")) {
          // Found a YAML key line that's not part of vault
          break;
        }
        vaultStartLine--;
      }
      vaultBlock = extractVaultBlock(document, vaultStartLine);
    }

    if (vaultBlock && getInlineTextType(vaultBlock) === "encrypted") {
      // We're on a vault - copy decrypted value to clipboard
      logs.appendLine(`📋 Copy decrypted value to clipboard`);
      const decrypted = await decryptVaultText(vaultBlock, editor.document.uri);
      if (decrypted) {
        await vscode.env.clipboard.writeText(decrypted);
        vscode.window.showInformationMessage("✅ Decrypted value copied to clipboard!");
      } else {
        vscode.window.showErrorMessage("Failed to decrypt vault");
      }
      return;
    }

    // Not on a vault - check if we're on a YAML key: value line
    const yamlMatch = lineText.match(/^(\s*)(\w[\w_]*)\s*:\s*(.+)$/);
    if (yamlMatch) {
      const [, indent, key, value] = yamlMatch;
      const trimmedValue = value.trim();
      
      // Don't encrypt if value is already a vault reference or empty
      if (trimmedValue.startsWith("!vault") || trimmedValue === "" || trimmedValue.startsWith("{{")) {
        vscode.window.showWarningMessage("Value is already encrypted or is a variable reference");
        return;
      }

      // Encrypt the value
      const { pass, vaultId } = await getPasswordAndVaultId(editor, trimmedValue);
      if (!pass) {
        return;
      }

      logs.appendLine(`🔒 Encrypt YAML value: ${key}`);
      const encryptedText = await encrypt(trimmedValue, pass, vaultId);
      if (encryptedText) {
        // Calculate indentation for the vault block
        const keyIndent = indent.length;
        const valueIndent = keyIndent + 4; // Standard YAML indent
        
        // Format the encrypted text with proper indentation
        const encryptedLines = encryptedText.split("\n");
        const formattedVault = encryptedLines
          .map((l, i) => (i === 0 ? l : " ".repeat(valueIndent) + l))
          .join("\n");
        
        // Replace the entire line
        const newLine = `${indent}${key}: !vault |\n${" ".repeat(valueIndent)}${formattedVault.replace("$ANSIBLE_VAULT", "$ANSIBLE_VAULT")}`;
        
        // Actually, let's use reindentText properly
        const fullRange = line.range;
        const indentLevel = Math.floor(keyIndent / Number(editor.options.tabSize || 4));
        const formattedText = reindentText(encryptedText, indentLevel, Number(editor.options.tabSize || 4));
        
        await editor.edit((editBuilder) => {
          editBuilder.replace(fullRange, `${indent}${key}: ${formattedText}`);
        });
        logs.appendLine(`✅ Encryption successful`);
      } else {
        vscode.window.showErrorMessage("Encryption failed");
      }
      return;
    }

    vscode.window.showWarningMessage("Place cursor on a YAML key: value line to encrypt, or on a vault to copy");
  };

  // File encrypt/decrypt - for entire files (F1 only)
  const fileEncryptDecrypt = async () => {
    logs.appendLine("🔐 Starting file encrypt/decrypt.");
    
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return;
    }

    const doc = editor.document;
    const content = doc.getText();
    const type = getTextType(content);

    // For file operations, we need to determine vault ID differently
    let checkText = content;
    const { pass, vaultId } = await getPasswordAndVaultId(editor, checkText);
    if (!pass) {
      return;
    }

    if (type === "plaintext") {
      logs.appendLine(`🔒 Encrypt entire file`);
      const encryptedText = await encrypt(content, pass, vaultId);
      if (encryptedText) {
        await editor.edit((builder) => {
          builder.replace(
            new vscode.Range(
              doc.lineAt(0).range.start,
              doc.lineAt(doc.lineCount - 1).range.end
            ),
            encryptedText
          );
        });
        vscode.window.showInformationMessage(`File encrypted: '${doc.fileName}'`);
        logs.appendLine(`✅ File encryption successful`);
      } else {
        vscode.window.showErrorMessage("Encryption failed");
      }
    } else if (type === "encrypted") {
      logs.appendLine(`🔓 Decrypt entire file`);
      const decryptedText = await decrypt(content, pass, vaultId);
      if (decryptedText === undefined) {
        vscode.window.showErrorMessage(`Decryption failed: Invalid Vault`);
      } else {
        await editor.edit((builder) => {
          builder.replace(
            new vscode.Range(
              doc.lineAt(0).range.start,
              doc.lineAt(doc.lineCount - 1).range.end
            ),
            decryptedText
          );
        });
        vscode.window.showInformationMessage(`File decrypted: '${doc.fileName}'`);
        logs.appendLine(`✅ File decryption successful`);
      }
    }
  };

  // Helper function to get password and vault ID
  const getPasswordAndVaultId = async (
    editor: vscode.TextEditor,
    text: string
  ): Promise<{ pass: string; vaultId: string }> => {
    let pass: string = "";

    // Read `ansible.cfg`
    logs.appendLine(`📋 Starting ansible.cfg scan...`);
    const configFileInWorkspacePath = getConfigFileInWorkspace(
      logs,
      editor.document.uri
    );
    let otherPath = findAnsibleCfgFile(
      logs,
      editor.document.uri.fsPath,
      "ansible.cfg"
    );

    if (otherPath !== undefined) {
      otherPath = verifyAnsibleDirectory(logs, editor.document.uri, otherPath);
    }

    const [keyInCfg, vaultIds, vaultPass] = scanAnsibleCfg(
      logs,
      otherPath,
      configFileInWorkspacePath
    );

    // Determine vault ID from text or prompt user
    let vaultId: string;
    const textType = getInlineTextType(text);
    if (textType === "encrypted") {
      vaultId = extractVaultId(text);
      logs.appendLine(`🔍 Extracted vault ID from encrypted content: '${vaultId}'`);
    } else {
      vaultId = await encryptVaultId(vaultIds) || "default";
      logs.appendLine(`🔍 Selected vault ID for encryption: '${vaultId}'`);
    }

    // Get password from ansible.cfg
    if (vaultPass) {
      if (vaultPass[vaultId] !== undefined) {
        pass = findPassword(logs, editor.document.uri.fsPath, vaultPass[vaultId]) || "";
      } else if (vaultPass["default"] !== undefined) {
        pass = findPassword(logs, editor.document.uri.fsPath, vaultPass["default"]) || "";
      }
    }

    if (!pass) {
      const inputPass = await vscode.window.showInputBox({ 
        prompt: "Enter the ansible-vault password:",
        password: true
      });
      pass = inputPass || "";
    }

    logs.appendLine(`🔐 Password status: ${pass ? 'loaded' : 'not loaded'}, vault ID: '${vaultId}'`);
    return { pass, vaultId: vaultId || "default" };
  };

  // Register CodeLens provider
  const codeLensProvider = new VaultedLineCodeLensProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { scheme: "file", pattern: "**/*.{yaml,yml}" },
      codeLensProvider
    )
  );

  // Register Hover provider for decrypted value preview
  const hoverProvider = new VaultHoverProvider();
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(
      { scheme: "file", pattern: "**/*.{yaml,yml}" },
      hoverProvider
    )
  );

  // Register copy decrypted value command
  const copyDecryptedCommand = vscode.commands.registerCommand(
    "extension.copyDecryptedVault",
    async (uri: vscode.Uri, line: number) => {
      const document = await vscode.workspace.openTextDocument(uri);
      const vaultText = extractVaultBlock(document, line);
      
      if (!vaultText) {
        vscode.window.showErrorMessage("Could not find vault block");
        return;
      }

      const decrypted = await decryptVaultText(vaultText, uri);
      if (decrypted) {
        await vscode.env.clipboard.writeText(decrypted);
        vscode.window.showInformationMessage("✅ Decrypted value copied to clipboard!");
      } else {
        vscode.window.showErrorMessage("Failed to decrypt vault");
      }
    }
  );
  context.subscriptions.push(copyDecryptedCommand);

  context.subscriptions.push(decryptCommand);

  // Cmd+Alt+V - Smart: encrypt plaintext OR copy decrypted vault
  const inlineCommand = vscode.commands.registerCommand(
    "extension.ansibleVault",
    inlineEncryptOrCopy
  );
  context.subscriptions.push(inlineCommand);

  // F1 only - File encrypt/decrypt
  const fileCommand = vscode.commands.registerCommand(
    "extension.ansibleVault.file",
    fileEncryptDecrypt
  );
  context.subscriptions.push(fileCommand);
}

export function deactivate() {}

const getIndentationLevel = (
  editor: vscode.TextEditor,
  selection: vscode.Selection
): number => {
  if (!editor.options.tabSize) {
    throw new Error(
      "The `tabSize` option is not defined, this should never happen."
    );
  }
  const startLine = editor.document.lineAt(selection.start.line).text;
  const indentationMatches = startLine.match(/^\s*/);
  const leadingWhitespaces = indentationMatches?.[0]?.length || 0;
  return leadingWhitespaces / Number(editor.options.tabSize);
};

const reindentText = (
  text: string,
  indentationLevel: number,
  tabSize: number
) => {
  const leadingSpacesCount = (indentationLevel + 1) * tabSize;
  const lines = text.split("\n");
  let trailingNewlines = 0;
  for (const line of lines.reverse()) {
    if (line === "") {
      trailingNewlines++;
    } else {
      break;
    }
  }
  lines.reverse();
  if (lines.length > 1) {
    const leadingWhitespaces = " ".repeat(leadingSpacesCount);
    const rejoinedLines = lines
      .map((line) => `${leadingWhitespaces}${line}`)
      .join("\n");
    rejoinedLines.replace(/\n$/, "");
    return `!vault |\n${rejoinedLines}`;
  }
  return text;
};

const encrypt = async (text: string, pass: string, encryptVaultId: any) => {
  logs.appendLine(`🔒 encrypt() called with:`);
  logs.appendLine(`  - text length: ${text.length}`);
  logs.appendLine(`  - password length: ${pass?.length || 0}`);
  logs.appendLine(`  - encryptVaultId: '${encryptVaultId}'`);
  logs.appendLine(`  - encryptVaultId type: ${typeof encryptVaultId}`);
  
  const vault = new Vault({ password: pass });
  try {
    let result;
    // For encryption: use empty string for default vault, or the specific vault ID
    const vaultIdForEncrypt = (encryptVaultId && encryptVaultId !== "default") ? encryptVaultId : "";
    logs.appendLine(`  - Calling vault.encrypt() with vault ID: '${vaultIdForEncrypt}' (empty string = default vault)`);
    result = (await vault.encrypt(text, vaultIdForEncrypt)) as string;
    logs.appendLine(`✅ Encryption successful, result length: ${result?.length || 0}`);
    return result;
  } catch (error: any) {
    logs.appendLine(`❌ Encryption failed: ${error.message}`);
    logs.appendLine(`❌ Error stack: ${error.stack}`);
    vscode.window.showErrorMessage(`Encryption failed: ${error.message}`);
    return undefined;
  }
};

const decrypt = async (text: string, pass: string, encryptVaultId: any) => {
  logs.appendLine(`🔓 decrypt() called with:`);
  logs.appendLine(`  - text length: ${text.length}`);
  logs.appendLine(`  - text first 50 chars: ${text.substring(0, 50)}`);
  logs.appendLine(`  - password length: ${pass?.length || 0}`);
  logs.appendLine(`  - password (hex): ${Buffer.from(pass, 'utf-8').toString('hex')}`);
  logs.appendLine(`  - password has newline: ${pass?.includes('\n') ? 'YES' : 'NO'}`);
  logs.appendLine(`  - password has carriage return: ${pass?.includes('\r') ? 'YES' : 'NO'}`);
  logs.appendLine(`  - password has tab: ${pass?.includes('\t') ? 'YES' : 'NO'}`);
  logs.appendLine(`  - encryptVaultId: '${encryptVaultId}'`);
  logs.appendLine(`  - encryptVaultId type: ${typeof encryptVaultId}`);
  
  const vault = new Vault({ password: pass });
  try {
    let result;
    // The ansible-vault library expects undefined (not empty string or "default") for vaults without ID
    if (encryptVaultId && encryptVaultId !== "default" && encryptVaultId !== "") {
      logs.appendLine(`  - Calling vault.decrypt() with vault ID: '${encryptVaultId}'`);
      result = (await vault.decrypt(text, encryptVaultId)) as string;
    } else {
      logs.appendLine(`  - Calling vault.decrypt() without vault ID (passing undefined for default vault)`);
      result = (await vault.decrypt(text, undefined)) as string;
    }
    logs.appendLine(`✅ Decryption successful, result length: ${result?.length || 0}`);
    return result;
  } catch (error: any) {
    logs.appendLine(`❌ Decryption failed: ${error.message}`);
    logs.appendLine(`❌ Error stack: ${error.stack}`);
    vscode.window.showErrorMessage(`Decryption failed: ${error.message}`);
    return undefined;
  }
};

const encryptVaultId = async (vaultIds: false | Array<string>) => {
  if (!vaultIds) {
    return "default";
  }
  // Ensure 'default' is in the list if we have vault IDs
  if (vaultIds.length > 0 && !vaultIds.includes("default")) {
    vaultIds.push("default");
  }
  if (vaultIds.length === 1) {
    return vaultIds[0];
  }
  return chooseVaultId(vaultIds);
};

const chooseVaultId = async (vaultIds: Array<string>) => {
  return vscode.window.showQuickPick(vaultIds, {
    placeHolder: "Choose ansible vault ID for encryption: ",
    canPickMany: false,
  });
};
