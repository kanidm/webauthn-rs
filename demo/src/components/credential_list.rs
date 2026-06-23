use crate::api::EnrolledPasskeyInfo;
use leptos::prelude::*;

#[component]
pub fn CredentialList(credentials: Vec<EnrolledPasskeyInfo>) -> impl IntoView {
    view! {
        <h3>
            "Enrolled passkeys ("
            {credentials.len()}
            ")"
        </h3>
        <table class="table">
            <thead>
                <tr>
                    <th>"Current"</th>
                    <th>"Credential ID"</th>
                    <th>"Enrollment time"</th>
                    <th>"Label"</th>
                </tr>
            </thead>

            <tbody>
                <For
                    each=move || credentials.clone().into_iter()
                    key=|c| c.cred_id_short.clone()
                    let(c)
                >
                    <tr
                        class=if c.current { "table-active" } else { "" }
                    >
                        <td>
                            <Show when=move || c.current>
                                "✅"
                            </Show>
                        </td>
                        <td><code>{hex::encode(c.cred_id_short)}"..."</code></td>
                        <td>{c.created.format(&time::format_description::well_known::Rfc2822)}</td>
                        <td>{c.label}</td>
                    </tr>
                </For>
            </tbody>
        </table>
    }
}
