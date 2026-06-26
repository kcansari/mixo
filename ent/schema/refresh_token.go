package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Refresh_Token holds the schema definition for the Refresh_Token entity.
type Refresh_Token struct {
	ent.Schema
}

// Fields of the Refresh_Token.
func (Refresh_Token) Fields() []ent.Field {
	return []ent.Field{
		field.String("token_hash").Unique(),
		field.Time("revoked_at").Optional().Nillable(),
		field.Time("created_at").Default(time.Now),
	}
}

// Edges of the Refresh_Token.
func (Refresh_Token) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).
			Ref("refresh_tokens").
			Unique(),
	}
}
