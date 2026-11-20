import ts from 'typescript-docs';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export type ApiInventory = Record<string, Record<string, string>>;
const fixture = new URL('../test/fixtures/public-api-inventory.json', import.meta.url);

// Expand callable queries: changing a private function used by an exported
// facade must change the inventory even when its `typeof` reference stays put.
function renderDeclaration(source: ts.SourceFile): string {
  const printer = ts.createPrinter({removeComments: true});
  const transformed = ts.transform(source, [context => {
    const f = context.factory;
    const sort = (members: readonly ts.TypeElement[]) => members.some(member => !ts.isPropertySignature(member))
      ? [...members] : [...members].sort((a, b) => {
      const x = printer.printNode(ts.EmitHint.Unspecified, a, source);
      const y = printer.printNode(ts.EmitHint.Unspecified, b, source);
      return x < y ? -1 : x > y ? 1 : 0;
    });
    const visit: ts.Visitor = node => {
      if (ts.isImportTypeNode(node) && node.qualifier && !node.isTypeOf) {
        return ts.visitEachChild(f.createTypeReferenceNode(node.qualifier, node.typeArguments), visit, context);
      }
      const visited = ts.visitEachChild(node, visit, context);
      if (ts.isParenthesizedTypeNode(visited)) return visited.type;
      if (ts.isTypeReferenceNode(visited) && ts.isIdentifier(visited.typeName) &&
        visited.typeName.text === 'Uint8Array' && visited.typeArguments?.length === 1) {
        const argument = visited.typeArguments[0]!;
        if (ts.isTypeReferenceNode(argument) && ts.isIdentifier(argument.typeName) && argument.typeName.text === 'ArrayBufferLike') {
          return f.createTypeReferenceNode('Uint8Array', undefined);
        }
      }
      if (ts.isMethodSignature(visited)) {
        return f.createPropertySignature(visited.modifiers, visited.name, visited.questionToken,
          f.createFunctionTypeNode(visited.typeParameters, visited.parameters,
            visited.type ?? f.createKeywordTypeNode(ts.SyntaxKind.VoidKeyword)));
      }
      if (ts.isTypeReferenceNode(visited) && ts.isIdentifier(visited.typeName) &&
        visited.typeName.text === 'Readonly' && visited.typeArguments?.length === 1) {
        const mark = (type: ts.TypeNode): ts.TypeNode => {
          if (ts.isTypeLiteralNode(type)) return f.createTypeLiteralNode(sort(type.members.map(member =>
            ts.isPropertySignature(member) ? f.updatePropertySignature(member,
              [f.createModifier(ts.SyntaxKind.ReadonlyKeyword)], member.name, member.questionToken, member.type) : member)));
          if (ts.isUnionTypeNode(type)) return f.createUnionTypeNode(type.types.map(mark));
          return f.createTypeReferenceNode('Readonly', [type]);
        };
        return mark(visited.typeArguments[0]!);
      }
      if (ts.isPropertySignature(visited) && ts.isStringLiteral(visited.name) &&
        /^[A-Za-z_$][\w$]*$/.test(visited.name.text)) {
        return f.updatePropertySignature(visited, visited.modifiers, f.createIdentifier(visited.name.text),
          visited.questionToken, visited.type);
      }
      if (ts.isTypeLiteralNode(visited)) return f.updateTypeLiteralNode(visited, f.createNodeArray(sort(visited.members)));
      if (ts.isClassDeclaration(visited)) {
        const marker = (member: ts.ClassElement) => member.name && ts.isPrivateIdentifier(member.name);
        return f.updateClassDeclaration(visited, visited.modifiers, visited.name, visited.typeParameters,
          visited.heritageClauses, [...visited.members.filter(marker), ...visited.members.filter(m => !marker(m))]);
      }
      if (ts.isVariableDeclaration(visited) && visited.initializer && !visited.type &&
        (ts.isStringLiteral(visited.initializer) || ts.isNumericLiteral(visited.initializer))) {
        return f.updateVariableDeclaration(visited, visited.name, visited.exclamationToken,
          f.createLiteralTypeNode(visited.initializer), undefined);
      }
      if (ts.isPropertyDeclaration(visited) && visited.initializer && !visited.type &&
        (ts.isStringLiteral(visited.initializer) || ts.isNumericLiteral(visited.initializer))) {
        return f.updatePropertyDeclaration(visited, visited.modifiers, visited.name, visited.questionToken,
          f.createLiteralTypeNode(visited.initializer), undefined);
      }
      return visited;
    };
    return node => ts.visitNode(node, visit) as ts.SourceFile;
  }]);
  try { return printer.printFile(transformed.transformed[0]!); }
  finally { transformed.dispose(); }
}

function declarationText(declaration: ts.Declaration, checker: ts.TypeChecker): string {
  const source = declaration.getSourceFile(), start = declaration.getStart(source);
  const edits: {start: number; end: number; text: string}[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isTypeQueryNode(node)) {
      const signatures = checker.getTypeAtLocation(node).getCallSignatures();
      if (signatures.length) {
        const texts = signatures.map(signature => checker.signatureToString(signature, node,
          ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.UseAliasDefinedOutsideCurrentScope |
          ts.TypeFormatFlags.WriteArrowStyleSignature, ts.SignatureKind.Call));
        const text = texts.length === 1 ? '(' + texts[0]! + ')' : '{' + texts.map(text => {
          const file = ts.createSourceFile('signature.d.ts', 'type T = ' + text + ';', ts.ScriptTarget.Latest, true);
          const alias = file.statements[0];
          if (!alias || !ts.isTypeAliasDeclaration(alias) || !ts.isFunctionTypeNode(alias.type)) throw new Error('Cannot render callable declaration');
          const type = alias.type;
          return ts.createPrinter({removeComments: true}).printNode(ts.EmitHint.Unspecified,
            ts.factory.createCallSignature(type.typeParameters, type.parameters, type.type), file);
        }).join('\n') + '}';
        edits.push({start: node.getStart(source) - start, end: node.end - start, text});
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(declaration);
  let text = declaration.getText(source);
  for (const edit of edits.sort((a, b) => b.start - a.start)) text = text.slice(0, edit.start) + edit.text + text.slice(edit.end);
  return ts.isVariableDeclaration(declaration) ? 'const ' + text + ';' : text;
}

export function canonicalSignature(signature: string): string {
  const source = ts.createSourceFile('inventory.d.ts', signature, ts.ScriptTarget.Latest, true);
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, ts.LanguageVariant.Standard, renderDeclaration(source));
  const tokens: string[] = [];
  for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
    const token = scanner.getTokenText();
    if (['export', 'declare', 'async', ';'].includes(token)) continue;
    tokens.push(kind === ts.SyntaxKind.StringLiteral ? JSON.stringify(scanner.getTokenValue()) :
      kind === ts.SyntaxKind.NumericLiteral ? String(Number(scanner.getTokenValue().replaceAll('_', ''))) : token);
  }
  return tokens.join(' ');
}

export function declarationInventory(): ApiInventory {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
    exports: Record<string, string | {types: string}>;
  };
  for (const [entry, target] of Object.entries(pkg.exports)) {
    if (typeof target === 'string' && entry !== './package.json') throw new Error(`Untyped package entry point: ${entry}`);
  }
  const entries = Object.entries(pkg.exports).filter((e): e is [string, {types: string}] => typeof e[1] !== 'string');
  const roots = entries.map(([, entry]) => resolve(entry.types));
  const program = ts.createProgram(roots, {
    target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext, skipLibCheck: true, noEmit: true,
  });
  const checker = program.getTypeChecker();
  const unalias = (symbol: ts.Symbol) => symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
  const publicSymbols = new Set<ts.Symbol>();
  for (const root of roots) {
    const file = program.getSourceFile(root), module = file && checker.getSymbolAtLocation(file);
    if (!module) throw new Error(`Missing declaration entry point: ${root}`);
    for (const symbol of checker.getExportsOfModule(module)) publicSymbols.add(unalias(symbol));
  }
  const referenced = (roots: readonly ts.Declaration[]): ts.Declaration[] => {
    const seen = new Set<ts.Symbol>(), support: ts.Declaration[] = [];
    const scan = (node: ts.Node): void => {
      const name = ts.isTypeReferenceNode(node) ? node.typeName : ts.isTypeQueryNode(node) ? node.exprName :
        ts.isImportTypeNode(node) ? node.qualifier : undefined;
      const found = name && checker.getSymbolAtLocation(name);
      const imported = ts.isImportTypeNode(node) ? checker.getTypeAtLocation(node) : undefined;
      const target = found ?? imported?.aliasSymbol ?? imported?.getSymbol();
      const symbol = target && unalias(target);
      if (symbol && !publicSymbols.has(symbol) && !seen.has(symbol)) {
        seen.add(symbol);
        for (const declaration of symbol.declarations ?? []) {
          if (declaration.getSourceFile().fileName.startsWith(resolve('dist') + '/')) {
            if (ts.isTypeAliasDeclaration(declaration) || ts.isInterfaceDeclaration(declaration) || ts.isVariableDeclaration(declaration)) {
              support.push(declaration); scan(declaration);
            } else if (ts.isFunctionDeclaration(declaration) || ts.isMethodDeclaration(declaration)) {
              scan(declaration);
            }
          }
        }
      }
      ts.forEachChild(node, scan);
    };
    roots.forEach(scan);
    return support.sort((a, b) => {
      const x = a.getSourceFile().fileName + ':' + a.getText(), y = b.getSourceFile().fileName + ':' + b.getText();
      return x < y ? -1 : x > y ? 1 : 0;
    });
  };
  const inventory: ApiInventory = Object.create(null);
  for (const [entry, target] of entries) {
    const source = program.getSourceFile(resolve(target.types));
    if (!source) throw new Error(`Missing ${target.types}; build before checking declaration inventory`);
    const module = checker.getSymbolAtLocation(source);
    if (!module) throw new Error(`Not a declaration entry point: ${target.types}`);
    const names: Record<string, string> = Object.create(null);
    for (const exported of checker.getExportsOfModule(module).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const symbol = unalias(exported);
      const typeOnly = exported.declarations?.some(declaration => ts.isExportSpecifier(declaration) &&
        (declaration.isTypeOnly || ts.isExportDeclaration(declaration.parent.parent) && declaration.parent.parent.isTypeOnly));
      const declarations = typeOnly ? symbol.declarations?.filter(declaration =>
        ts.isTypeAliasDeclaration(declaration) || ts.isInterfaceDeclaration(declaration) || ts.isClassDeclaration(declaration)) : symbol.declarations;
      if (!declarations?.length) throw new Error(`Missing declaration: ${entry} ${exported.name}`);
      const selection = typeOnly ? `export type { ${symbol.name}${exported.name === symbol.name ? '' : ' as ' + exported.name} };\n` : '';
      names[exported.name] = selection + [...declarations, ...referenced(declarations)].map(node => declarationText(node, checker)).join('\n');
    }
    inventory[entry] = names;
  }
  return inventory;
}

export function inventoryChanges(expected: ApiInventory, actual: ApiInventory): string[] {
  const changes: string[] = [];
  for (const entry of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()) {
    for (const name of [...new Set([...Object.keys(expected[entry] ?? {}), ...Object.keys(actual[entry] ?? {})])].sort()) {
      const before = expected[entry]?.[name], after = actual[entry]?.[name];
      if (before === undefined) changes.push(`added ${entry} ${name}: ${after}`);
      else if (after === undefined) changes.push(`removed ${entry} ${name}: ${before}`);
      else if (canonicalSignature(before) !== canonicalSignature(after)) changes.push(`changed ${entry} ${name}\n  was: ${before}\n  now: ${after}`);
    }
    if (!Object.hasOwn(expected, entry)) changes.push(`added entry point ${entry}`);
    else if (!Object.hasOwn(actual, entry)) changes.push(`removed entry point ${entry}`);
  }
  return changes;
}

// Tests never update the baseline. An update is an explicit reviewed edit.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--write') throw new Error('Expected --write after a hosted build');
  writeFileSync(fixture, JSON.stringify(declarationInventory(), null, 2) + '\n');
}
