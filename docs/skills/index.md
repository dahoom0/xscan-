# Skills

Skills are knowledge packs that give LLM specialists framework-specific
security methodology.

---

## Commands

```bash
xscan skills list
xscan skills install react-security
xscan skills install angular-security graphql-security
xscan skills inspect react-security
xscan skills update
xscan skills remove react-security
```

---

## Available skills

| Skill                | Frameworks / Focus                |
|----------------------|-----------------------------------|
| `react-security`     | React, JSX, dangerouslySetInnerHTML|
| `angular-security`   | Angular, templateUrl, bypassSecurity|
| `vue-security`       | Vue, v-html, template injection   |
| `graphql-security`   | GraphQL introspection, injection  |
| `jwt-security`       | JWT parsing, alg confusion        |
| `oauth-security`     | OAuth2/OIDC flows, redirect issues|
| `dom-clobbering`     | DOM clobbering attack patterns    |
| `prototype-pollution`| Prototype pollution sinks         |
| `template-injection` | Server-side template injection    |

---

## Skill storage

Skills are stored in `~/.xscan/skills/<skill-name>/`.

---

## Creating a custom skill

```bash
xscan skills create --name my-skill
```

This generates a skeleton in `~/.xscan/skills/my-skill/` with:

- `skill.toml`
- `sinks.json`
- `payloads.json`
- `references.md`

---

## Related topics

- `xscan help concepts/skills`
- `xscan help concepts/specialists`
