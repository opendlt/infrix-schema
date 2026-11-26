// Copyright 2024 The Infrix Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package policyeval

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// TokenType identifies lexer token types.
type TokenType int

const (
	TokEOF TokenType = iota
	TokNumber
	TokFloat
	TokString
	TokBool
	TokIdent
	TokLParen
	TokRParen
	TokComma
	TokDot
	TokColonColon // ::
	TokEqEq       // ==
	TokNotEq      // !=
	TokGt         // >
	TokLt         // <
	TokGte        // >=
	TokLte        // <=
	TokAnd        // AND
	TokOr         // OR
	TokNot        // NOT
	TokFor        // FOR
	TokBlocks     // BLOCKS
)

// Token is a single lexer token.
type Token struct {
	Type    TokenType
	Value   string
	IntVal  int64
	FltVal  float64
	BoolVal bool
	Pos     int
}

// Lexer tokenizes a policy expression string.
type Lexer struct {
	input  string
	pos    int
	tokens []Token
}

// NewLexer creates a lexer for the given input.
func NewLexer(input string) *Lexer {
	return &Lexer{input: input}
}

// Tokenize produces all tokens from the input.
func (l *Lexer) Tokenize() ([]Token, error) {
	for l.pos < len(l.input) {
		l.skipWhitespace()
		if l.pos >= len(l.input) {
			break
		}

		ch := l.input[l.pos]

		switch {
		case ch == '(':
			l.tokens = append(l.tokens, Token{Type: TokLParen, Value: "(", Pos: l.pos})
			l.pos++
		case ch == ')':
			l.tokens = append(l.tokens, Token{Type: TokRParen, Value: ")", Pos: l.pos})
			l.pos++
		case ch == ',':
			l.tokens = append(l.tokens, Token{Type: TokComma, Value: ",", Pos: l.pos})
			l.pos++
		case ch == '.':
			l.tokens = append(l.tokens, Token{Type: TokDot, Value: ".", Pos: l.pos})
			l.pos++
		case ch == ':' && l.peek() == ':':
			l.tokens = append(l.tokens, Token{Type: TokColonColon, Value: "::", Pos: l.pos})
			l.pos += 2
		case ch == '=' && l.peek() == '=':
			l.tokens = append(l.tokens, Token{Type: TokEqEq, Value: "==", Pos: l.pos})
			l.pos += 2
		case ch == '!' && l.peek() == '=':
			l.tokens = append(l.tokens, Token{Type: TokNotEq, Value: "!=", Pos: l.pos})
			l.pos += 2
		case ch == '>' && l.peek() == '=':
			l.tokens = append(l.tokens, Token{Type: TokGte, Value: ">=", Pos: l.pos})
			l.pos += 2
		case ch == '<' && l.peek() == '=':
			l.tokens = append(l.tokens, Token{Type: TokLte, Value: "<=", Pos: l.pos})
			l.pos += 2
		case ch == '>':
			l.tokens = append(l.tokens, Token{Type: TokGt, Value: ">", Pos: l.pos})
			l.pos++
		case ch == '<':
			l.tokens = append(l.tokens, Token{Type: TokLt, Value: "<", Pos: l.pos})
			l.pos++
		case ch == '"':
			tok, err := l.readString()
			if err != nil {
				return nil, err
			}
			l.tokens = append(l.tokens, tok)
		case unicode.IsDigit(rune(ch)) || (ch == '-' && l.pos+1 < len(l.input) && unicode.IsDigit(rune(l.input[l.pos+1]))):
			tok, err := l.readNumber()
			if err != nil {
				return nil, err
			}
			l.tokens = append(l.tokens, tok)
		case unicode.IsLetter(rune(ch)) || ch == '_':
			l.tokens = append(l.tokens, l.readIdentifier())
		default:
			return nil, fmt.Errorf("unexpected character '%c' at position %d", ch, l.pos)
		}
	}

	l.tokens = append(l.tokens, Token{Type: TokEOF, Pos: l.pos})
	return l.tokens, nil
}

func (l *Lexer) peek() byte {
	if l.pos+1 < len(l.input) {
		return l.input[l.pos+1]
	}
	return 0
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && (l.input[l.pos] == ' ' || l.input[l.pos] == '\t' || l.input[l.pos] == '\n' || l.input[l.pos] == '\r') {
		l.pos++
	}
}

func (l *Lexer) readString() (Token, error) {
	start := l.pos
	l.pos++ // skip opening "
	for l.pos < len(l.input) && l.input[l.pos] != '"' {
		l.pos++
	}
	if l.pos >= len(l.input) {
		return Token{}, fmt.Errorf("unterminated string at position %d", start)
	}
	val := l.input[start+1 : l.pos]
	l.pos++ // skip closing "
	return Token{Type: TokString, Value: val, Pos: start}, nil
}

// readNumber reads a number literal. A literal that does not parse ("1.2.3", or an integer past int64) is an error: it used to read as
// 0 (or the int64 bound), so the rule compared against a number nobody wrote.
func (l *Lexer) readNumber() (Token, error) {
	start := l.pos
	if l.input[l.pos] == '-' {
		l.pos++
	}
	isFloat := false
	for l.pos < len(l.input) && (unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '.') {
		if l.input[l.pos] == '.' {
			isFloat = true
		}
		l.pos++
	}
	val := l.input[start:l.pos]
	if isFloat {
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return Token{}, fmt.Errorf("number %q at position %d does not parse: %w", val, start, err)
		}
		return Token{Type: TokFloat, Value: val, FltVal: f, Pos: start}, nil
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return Token{}, fmt.Errorf("number %q at position %d does not parse: %w", val, start, err)
	}
	return Token{Type: TokNumber, Value: val, IntVal: n, Pos: start}, nil
}

func (l *Lexer) readIdentifier() Token {
	start := l.pos
	for l.pos < len(l.input) && (unicode.IsLetter(rune(l.input[l.pos])) || unicode.IsDigit(rune(l.input[l.pos])) || l.input[l.pos] == '_') {
		l.pos++
	}
	val := l.input[start:l.pos]

	upper := strings.ToUpper(val)
	switch upper {
	case "AND":
		return Token{Type: TokAnd, Value: val, Pos: start}
	case "OR":
		return Token{Type: TokOr, Value: val, Pos: start}
	case "NOT":
		return Token{Type: TokNot, Value: val, Pos: start}
	case "FOR":
		return Token{Type: TokFor, Value: val, Pos: start}
	case "BLOCKS":
		return Token{Type: TokBlocks, Value: val, Pos: start}
	case "TRUE":
		return Token{Type: TokBool, Value: val, BoolVal: true, Pos: start}
	case "FALSE":
		return Token{Type: TokBool, Value: val, BoolVal: false, Pos: start}
	}

	return Token{Type: TokIdent, Value: val, Pos: start}
}
