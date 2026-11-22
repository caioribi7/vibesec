// Frontend propositalmente vulnerável (fixture de teste)
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);

export function render(comment) {
  document.getElementById("out").innerHTML = comment.body;
  const sessionToken = Math.random().toString(36);
  return eval(comment.expr) + sessionToken;
}

export async function search(db, term) {
  return db.query(`SELECT * FROM posts WHERE title LIKE '%${term}%'`);
}

export default supabase;
