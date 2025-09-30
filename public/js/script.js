const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const on = (el, ev, cb, opts) => el && el.addEventListener(ev, cb, opts);

(function () {
  const zones = ["old", "mid", "new"];
  const zoneEls = Object.fromEntries(
    zones.map((z) => [z, document.getElementById(`zone-${z}`)])
  );
  const tabs = $$(".zone-tab");

  function setActiveTab(btn, active) {
    btn.classList.toggle("bg-blue-600", active);
    btn.classList.toggle("text-white", active);
    btn.classList.toggle("shadow", active);
    btn.classList.toggle("bg-gray-100", !active);
    btn.classList.toggle("text-gray-700", !active);
  }

  function showZone(zone) {
    zones.forEach((z) => zoneEls[z]?.classList.toggle("hidden", z !== zone));
    tabs.forEach((btn) => setActiveTab(btn, btn.dataset.zone === zone));
    history.replaceState(null, "", `#zone-${zone}`);
  }
  tabs.forEach((btn) => on(btn, "click", () => showZone(btn.dataset.zone)));
  const fromHash = (location.hash || "").replace("#", "");
  if (zones.some((z) => `zone-${z}` === fromHash)) {
    showZone(fromHash.replace("zone-", ""));
  } else {
    showZone("old");
  }
})();

const ROOM_DB = {
  15: {
    type: "ห้องแอร์บิ้วอิน",
    price: 4500,
    status: "vacant",
    photo:
      "https://images.unsplash.com/photo-1505691723518-36a5ac3b2a81?q=80&w=1200&auto=format&fit=crop",
    amenities: [
      "เตียง 6 ฟุต",
      "ตู้เสื้อผ้าบิ้วอิน",
      "โต๊ะทำงาน",
      "เครื่องทำน้ำอุ่น",
      "เครื่องปรับอากาศ",
      "ตู้เย็น",
    ],
  },
  16: {
    type: "ห้องแอร์",
    price: 3000,
    status: "busy",
    photo:
      "https://images.unsplash.com/photo-1501045661006-fcebe0257c3f?q=80&w=1200&auto=format&fit=crop",
    amenities: [
      "เตียง 6 ฟุต",
      "ตู้เสื้อผ้า",
      "โต๊ะทำงาน",
      "เครื่องทำน้ำอุ่น",
      "เครื่องปรับอากาศ",
      "ตู้เย็น",
    ],
  },
  17: {
    type: "ห้องแอร์",
    price: 3000,
    status: "busy",
    photo: "",
    amenities: ["เตียง 6 ฟุต", "เครื่องทำน้ำอุ่น"],
  },
  18: {
    type: "ห้องแอร์บิ้วอิน",
    price: 4500,
    status: "vacant",
    photo: "",
    amenities: ["เตียง 6 ฟุต", "บิ้วอิน", "แอร์"],
  },
  19: {
    type: "ห้องแอร์",
    price: 3000,
    status: "busy",
    photo: "",
    amenities: ["เตียง 6 ฟุต"],
  },
  20: {
    type: "ห้องแอร์บิ้วอิน",
    price: 4500,
    status: "vacant",
    photo: "",
    amenities: ["เตียง 6 ฟุต", "แอร์", "ตู้เย็น"],
  },
  "01": {
    type: "ห้องแอร์",
    price: 3000,
    status: "busy",
    photo: "",
    amenities: [],
  },
  "02": {
    type: "ห้องแอร์",
    price: 3000,
    status: "vacant",
    photo: "",
    amenities: [],
  },
  "05": {
    type: "ห้องแอร์",
    price: 3000,
    status: "vacant",
    photo: "",
    amenities: [],
  },
  "08": {
    type: "ห้องแอร์",
    price: 3000,
    status: "busy",
    photo: "",
    amenities: [],
  },
  "09": {
    type: "ห้องแอร์",
    price: 3000,
    status: "vacant",
    photo: "",
    amenities: ["เตียง 6 ฟุต", "แอร์", "ตู้เย็น"],
  },
  12: {
    type: "ห้องแอร์บิ้วอิน",
    price: 4500,
    status: "vacant",
    photo: "",
    amenities: [],
  },
};

function paintRoomBox(el, status) {
  el.classList.remove("bg-blue-600", "text-white", "font-semibold", "shadow");
  el.classList.remove("bg-gray-100", "text-gray-500");
  if (status === "vacant") {
    el.classList.add("bg-blue-600", "text-white", "font-semibold", "shadow");
  } else {
    el.classList.add("bg-gray-100", "text-gray-500");
  }
}

function paintAllFromDB() {
  $$(".room[data-room]").forEach((el) => {
    const id = el.dataset.room;
    const rec = ROOM_DB[id];
    if (rec) paintRoomBox(el, rec.status);
  });
}
paintAllFromDB();

const roomModal = $("#roomModal");
const rmOverlay = $("#roomModalOverlay");
const rmClose = $("#roomModalClose");
const mTitle = $("#m-title");
const mPhoto = $("#m-photo");
const mType = $("#m-type");
const mPrice = $("#m-price");
const mStatus = $("#m-status");
const mAmen = $("#m-amenities");
const mCTA = $("#m-cta");

function setStatusBadge(el, status) {
  el.classList.remove(
    "bg-blue-600",
    "bg-gray-100",
    "text-gray-700",
    "text-white"
  );
  if (status === "vacant") {
    el.textContent = "ว่าง";
    el.classList.add("bg-blue-600", "text-white");
  } else {
    el.textContent = "ไม่ว่าง";
    el.classList.add("bg-gray-100", "text-gray-700");
  }
}

function openModalFor(roomId) {
  const rec = ROOM_DB[roomId];
  if (!rec) return;
  mTitle.textContent = `รายละเอียดห้อง ${roomId}`;
  mType.textContent = rec.type || "-";
  mPrice.textContent = rec.price
    ? `${rec.price.toLocaleString()} บาท/เดือน`
    : "-";
  mPhoto.src =
    rec.photo ||
    "https://images.unsplash.com/photo-1505691723518-36a5ac3b2a81?q=80&w=1200&auto=format&fit=crop";
  setStatusBadge(mStatus, rec.status);
  mAmen.innerHTML = "";
  (rec.amenities || []).forEach((a) => {
    const li = document.createElement("li");
    li.textContent = a;
    mAmen.appendChild(li);
  });
  mCTA.disabled = rec.status !== "vacant";
  mCTA.textContent =
    rec.status === "vacant" ? "ติดต่อเพื่อจองห้องนี้" : "ห้องนี้ไม่ว่าง";
  roomModal.classList.remove("hidden");
}
function closeRoomModal() {
  roomModal.classList.add("hidden");
}
on(rmOverlay, "click", closeRoomModal);
on(rmClose, "click", closeRoomModal);

document.addEventListener("click", (e) => {
  const box = e.target.closest(".room[data-room]");
  if (!box) return;
  openModalFor(box.dataset.room);
});
document.addEventListener("keydown", (e) => {
  const el = e.target;
  if (!el.classList?.contains("room") || !el.dataset?.room) return;
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    openModalFor(el.dataset.room);
  }
});

(() => {
  const openBtn = $("#openLogin");
  const modal = $("#loginModal");
  const overlay = $("#loginOverlay");
  const closeBtn = $("#closeLogin");
  const form = $("#loginForm");
  const email = $("#email");
  const password = $("#password");
  const loginBtn = $("#loginBtn");
  const togglePwd = $("#togglePwd");
  const emailErr = $("#emailErr");
  const pwdErr = $("#pwdErr");
  const formAlert = $("#formAlert");
  const remember = $("#remember");

  let previousFocus = null;

  function trapFocus(container) {
    previousFocus = document.activeElement;
    const focusable = container.querySelectorAll(
      'button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])'
    );
    const first = focusable[0],
      last = focusable[focusable.length - 1];
    function loop(e) {
      if (e.key !== "Tab") return;
      if (e.shiftKey && document.activeElement === first) {
        last.focus();
        e.preventDefault();
      } else if (!e.shiftKey && document.activeElement === last) {
        first.focus();
        e.preventDefault();
      }
    }
    container.addEventListener("keydown", loop);
    container.__trap = loop;
  }
  function releaseFocus() {
    const loop = modal.__trap;
    if (loop) modal.removeEventListener("keydown", loop);
    previousFocus && previousFocus.focus();
  }

  function openModal() {
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    setTimeout(() => email?.focus(), 0);
    trapFocus(modal);
  }
  function closeModal() {
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
    releaseFocus();
    form?.reset();
    clearErrors();
    setLoading(false);
  }

  function clearErrors() {
    emailErr?.classList.add("hidden");
    pwdErr?.classList.add("hidden");
    formAlert?.classList.add("hidden");
    if (formAlert) formAlert.textContent = "";
  }
  function setLoading(v) {
    if (!loginBtn) return;
    loginBtn.disabled = v;
    loginBtn.innerHTML = v
      ? `<svg class="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
           <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
           <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path>
         </svg> กำลังเข้าสู่ระบบ...`
      : "เข้าสู่ระบบ";
  }
  function validate() {
    let ok = true;
    clearErrors();
    if (!email?.value || !/^\S+@\S+\.\S+$/.test(email.value)) {
      emailErr?.classList.remove("hidden");
      ok = false;
    }
    if (!password?.value || password.value.length < 6) {
      pwdErr?.classList.remove("hidden");
      ok = false;
    }
    return ok;
  }

  on(openBtn, "click", openModal);
  on(closeBtn, "click", closeModal);
  on(overlay, "click", closeModal);
  document.addEventListener("keydown", (e) => {
    if (!modal.classList.contains("hidden") && e.key === "Escape") closeModal();
  });

  on(togglePwd, "click", () => {
    if (!password) return;
    const type =
      password.getAttribute("type") === "password" ? "text" : "password";
    password.setAttribute("type", type);
    togglePwd.textContent = type === "password" ? "👁️" : "🙈";
    password.focus();
  });

  on(form, "submit", async (e) => {
    e.preventDefault();
    if (!validate()) return;
    setLoading(true);

    if (remember?.checked) localStorage.setItem("bk_saved_email", email.value);
    else localStorage.removeItem("bk_saved_email");

    try {
      await new Promise((r) => setTimeout(r, 700));
      if (password.value !== "123456")
        throw new Error("อีเมลหรือรหัสผ่านไม่ถูกต้อง");
      closeModal();
    } catch (err) {
      if (formAlert) {
        formAlert.textContent = err.message || "เกิดข้อผิดพลาด กรุณาลองใหม่";
        formAlert.classList.remove("hidden");
      }
    } finally {
      setLoading(false);
    }
  });

  const saved = localStorage.getItem("bk_saved_email");
  if (saved && email) {
    email.value = saved;
    if (remember) remember.checked = true;
  }
  if (location.hash === "#login") openModal();
})();

(function () {
  const header = document.querySelector("header.sticky");
  const HEADER_OFFSET = header?.offsetHeight || 72;
  document.querySelectorAll('a[href^="#"]').forEach((a) => {
    a.addEventListener("click", (e) => {
      let hash = a.getAttribute("href");
      if (!hash || hash === "#") return;
      if (hash === "#q&a") hash = "#faq";
      const id = decodeURIComponent(hash.slice(1));
      const target = document.getElementById(id);
      if (!target) return;
      e.preventDefault();
      const y =
        target.getBoundingClientRect().top + window.pageYOffset - HEADER_OFFSET;
      window.scrollTo({ top: y, behavior: "smooth" });
      history.pushState(null, "", hash);
    });
  });

  const shadowClass = "shadow-[0_6px_24px_rgba(15,23,42,.08)]";
  window.addEventListener("scroll", () => {
    if (!header) return;
    if (window.scrollY > 6) header.classList.add(shadowClass);
    else header.classList.remove(shadowClass);
  });

  const sections = ["home", "rooms", "status", "faq", "contact"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);

  const navLinks = document.querySelectorAll('nav a[href^="#"]');
  const byHash = {};
  navLinks.forEach((a) => {
    const href =
      a.getAttribute("href") === "#q&a" ? "#faq" : a.getAttribute("href");
    byHash[href] = a;
  });

  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return;
        const id = `#${en.target.id}`;
        navLinks.forEach((l) =>
          l.classList.remove("text-primary-700", "font-semibold")
        );
        const active = byHash[id];
        active?.classList.add("text-primary-700", "font-semibold");
      });
    },
    { rootMargin: "-35% 0px -55% 0px", threshold: 0.01 }
  );

  sections.forEach((sec) => io.observe(sec));
})();

(function () {
  const contactForm = $("#contact form");
  if (!contactForm) return;

  on(contactForm, "submit", async (e) => {
    e.preventDefault();
    const [nameInput, emailInput, msgInput] = $$(
      "input, textarea",
      contactForm
    );

    const errs = [];
    if (!nameInput?.value?.trim()) errs.push("กรุณากรอกชื่อ");
    if (!emailInput?.value || !/^\S+@\S+\.\S+$/.test(emailInput.value))
      errs.push("อีเมลไม่ถูกต้อง");
    if (!msgInput?.value?.trim()) errs.push("กรุณากรอกข้อความ");

    if (errs.length) {
      alert(errs.join("\n"));
      return;
    }
    try {
      await new Promise((r) => setTimeout(r, 600));
      alert("ส่งข้อความเรียบร้อย ขอบคุณค่ะ/ครับ");
      contactForm.reset();
    } catch {
      alert("ส่งข้อความไม่สำเร็จ กรุณาลองใหม่");
    }
  });
})();

(function () {
  if (window.lucide && typeof window.lucide.createIcons === "function") {
    window.lucide.createIcons();
  }
})();

(function () {
  const m = location.hash.match(/^#room-(\w+)$/i);
  if (m) openModalFor?.(m[1]);
})();

function toggleLogin() {
  const modal = document.getElementById("loginModal");
  modal.classList.toggle("hidden");
}

function togglePassword(btn) {
  const pwd = document.getElementById("password");
  const eyeIcon = btn.querySelector("svg");

  if (pwd.type === "password") {
    pwd.type = "text";
    eyeIcon.innerHTML = `
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M3 3l18 18M10.73 5.08A9.958 9.958 0 0112 5c4.64 0 8.573 3.008 9.963 7.178a1.012 1.012 0 010 .639A10.025 10.025 0 0112 19c-1.266 0-2.475-.234-3.59-.662M6.1 6.1A9.978 9.978 0 002.037 11.68a1.012 1.012 0 000 .64A9.978 9.978 0 006.1 17.9M9.88 9.88a3 3 0 104.24 4.24" />
    `;
  } else {
    pwd.type = "password";
    eyeIcon.innerHTML = `
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.008 9.963 7.178.07.207.07.432 0 .639C20.573 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.008-9.963-7.178z" />
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
        d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    `;
  }
}

document.getElementById("loginForm").addEventListener("submit", function (e) {
  e.preventDefault();
  const email = document.getElementById("email").value.trim();
  const pwd = document.getElementById("password").value.trim();
  if (!email || !pwd) {
    alert("กรุณากรอกอีเมลและรหัสผ่าน");
    return;
  }
  if (email === "test@email.com" && pwd === "1234") {
    alert("เข้าสู่ระบบสำเร็จ!");
    toggleLogin();
  } else {
    alert("อีเมลหรือรหัสผ่านไม่ถูกต้อง");
  }
});
