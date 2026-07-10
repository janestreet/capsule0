open! Import

module Access = struct
  type 'k t = 'k Prim.Access.t
  type packed = Prim.Access.packed = P : 'k t -> packed [@@unboxed]
  type 'k boxed = 'k Prim.Access.boxed

  let current = Prim.current
  let unbox = Prim.Access.unbox
  let box = Prim.Access.box
end

module Key = struct
  type 'k t = 'k Prim.Key.t

  let%template access = (Prim.Key.access [@mode l]) [@@mode l = (local, global)]
  let globalize_unique = Prim.Key.globalize_unique
  let destroy = Prim.Key.destroy
end

module Data = struct
  type ('a, 'k) t = ('a, 'k) Prim.Data.t

  let create = Prim.Data.create
  let wrap = Prim.Data.wrap
  let unwrap = Prim.Data.unwrap
  let%template[@mode global shared] unwrap = Prim.Data.unwrap_shared
  let return = Prim.Data.inject
  let get_id = Prim.Data.project
  let project_shared = Prim.Data.project_shared
  let both = Prim.Data.both
  let fst = Prim.Data.fst
  let snd = Prim.Data.snd

  [%%template
  [@@@mode.default unique]

  let create = Prim.Data.create_unique
  let unwrap = Prim.Data.unwrap_unique]

  [%%template
  [@@@mode.default local]

  let create = Prim.Data.Local.create
  let wrap = Prim.Data.Local.wrap
  let unwrap = Prim.Data.Local.unwrap
  let[@mode local shared] unwrap = Prim.Data.Local.unwrap_shared
  let return = Prim.Data.Local.inject
  let get_id = Prim.Data.Local.project
  let project_shared = Prim.Data.Local.project_shared
  let both = Prim.Data.Local.both
  let fst = Prim.Data.Local.fst
  let snd = Prim.Data.Local.snd

  [@@@mode.default unique]

  let create = Prim.Data.Local.create_unique
  let unwrap = Prim.Data.Local.unwrap_unique]
end

module Initial = struct
  type k = Prim.initial

  let access = Prim.initial

  module Data = struct
    type 'a t = ('a, k) Data.t

    [%%template
    [@@@mode.default l = (global, local)]

    let wrap a = (Data.wrap [@mode l]) ~access a [@exclave_if_local l]
    let unwrap a = (Data.unwrap [@mode l]) ~access a [@exclave_if_local l]]

    let sexp_of_t sexp_of_a t = sexp_of_a (unwrap t)
    let t_of_sexp a_of_sexp a = wrap (a_of_sexp a)
  end
end

module%template Isolated = struct
  module Repr = struct
    type ('a, 'k) inner =
      { data : ('a, 'k) Data.t
      ; key : 'k Key.t
      }

    type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]
  end

  (* We use this type declaration just as justification for the kind annotation on ['a t]. *)
  type ('a, 'k) _inner = ('a, 'k) Repr.inner
  type 'a t

  [@@@mode.default.explicit u = (unique, aliased)]

  external unsafe_to_data
    :  ('a t[@local_opt])
    -> (('a, 'k) Data.t[@local_opt])
    = "%identity"

  external unsafe_of_data
    :  (('a, 'k) Data.t[@local_opt])
    -> ('a t[@local_opt])
    = "%identity"

  [@@@mode.default.explicit l = (global, local)]

  let to_repr t =
    (let (P key) = Prim.create () in
     let data = (unsafe_to_data [@mode.explicit u]) t in
     Repr.P { data; key })
    [@exclave_if_local l ~reasons:[ May_return_regional ]]
  ;;

  let of_repr (Repr.P { data; key = _ }) =
    (unsafe_of_data [@mode.explicit u]) data [@exclave_if_local l]
  ;;
end

module%template Frozen = struct
  type 'a t = 'a portable Isolated.t

  [@@@mode.default l = (global, local)]

  let to_repr = (Isolated.to_repr [@mode.explicit aliased l])
  let of_repr = (Isolated.of_repr [@mode.explicit aliased l])

  let create f =
    (let (P key) = Prim.create () in
     let data =
       (Data.create [@mode l]) (fun () ->
         { portable = f () } [@exclave_if_local l ~reasons:[ May_return_local ]])
     in
     (of_repr [@mode l]) (P { key; data }))
    [@exclave_if_local l ~reasons:[ May_return_local ]]
  ;;

  let unwrap t =
    (let (P { key; data }) = (to_repr [@mode l]) t in
     ((Data.project_shared [@mode l]) ~key data).portable)
    [@exclave_if_local l ~reasons:[ May_return_regional ]]
  ;;
end

module%template Owned = struct
  type 'a t = 'a Isolated.t

  [@@@mode.default l = (global, local)]

  let to_repr = (Isolated.to_repr [@mode.explicit l unique])
  let of_repr = (Isolated.of_repr [@mode.explicit l unique])

  let create f =
    (let (P key) = Prim.create () in
     let data = (Data.create [@mode l unique]) f in
     (of_repr [@mode l]) (P { key; data }))
    [@exclave_if_local l ~reasons:[ May_return_local ]]
  ;;

  let freeze t =
    (let open struct
       (*_ Safe because ['a = 'a portable] for ('a : value mod portable) *)
       external wrap_portable
         : 'a 'k.
         ('a, 'k) Prim.Data.t -> ('a portable, 'k) Prim.Data.t
         = "%identity"
     end in
     let (P { data; key }) = (Isolated.to_repr [@mode.explicit l aliased]) t in
     let data = wrap_portable data in
     (Isolated.of_repr [@mode.explicit l aliased]) (P { data; key }))
    [@exclave_if_local l ~reasons:[ May_return_local ]]
  ;;

  let unwrap t =
    (let (P { key; data }) = (to_repr [@mode l]) t in
     let access = Key.destroy key in
     (Data.unwrap [@mode l unique]) ~access data)
    [@exclave_if_local l ~reasons:[ May_return_regional ]]
  ;;

  let dup (type a) (t : a) : a * a =
    (t, t) [@exclave_if_local l ~reasons:[ May_return_regional ]]
  ;;

  let get_contended (type a) (t : a t) : a t * a =
    (let (P { data; key }) = (to_repr [@mode l]) t in
     let data, data' = (dup [@mode l]) data in
     let t = (of_repr [@mode l]) (P { data; key }) in
     t, (Data.get_id [@mode l]) data')
    [@exclave_if_local l ~reasons:[ May_return_regional ]]
  ;;

  let with_ (type a) (t : a t) ~f =
    (let (P { key; data }) = (to_repr [@mode l]) t in
     let key = Key.globalize_unique key in
     let data, data' = (dup [@mode l]) data in
     let result, key =
       (Key.access [@mode l]) key ~f:(fun access ->
         { many = f ((Data.unwrap [@mode l]) ~access data') }
         [@exclave_if_local l ~reasons:[ May_return_local ]])
     in
     let t = (of_repr [@mode l]) (P { key; data }) in
     t, result.many)
    [@exclave_if_local l ~reasons:[ May_return_local ]]
  ;;
end

module Scoped = struct
  type ('a, 'k) inner =
    { data : ('a, 'k) Data.t
    ; password : 'k Prim.Password.t
    }

  type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]

  let%template[@inline] with_ a ~f =
    let (P access) = Access.current () in
    let data = Data.wrap ~access a in
    ((Prim.Password.with_current [@mode local]) access (fun password ->
       { aliased_many = { global = f (P { data; password }) } }))
      .aliased_many
      .global
  ;;

  let[@inline] get (P { data; password }) ~f =
    (Prim.Data.extract data ~password ~f:(fun a -> { many = { aliased = f a } })).many
      .aliased
  ;;

  let iter = get

  let[@inline] map (P { data; password }) ~f =
    P { data = Prim.Data.map data ~password ~f; password }
  ;;

  module Shared = struct
    type ('a, 'k) inner =
      { data : ('a shared, 'k) Data.t
      ; password : 'k Prim.Password.Shared.t
      }

    type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]

    module Uncontended = struct
      type ('a, 'k) t = ('a, 'k) inner =
        { data : ('a shared, 'k) Data.t
        ; password : 'k Prim.Password.Shared.t
        }

      type ('a, 'b) f = { f : 'k. ('a, 'k) inner -> ('b, 'k) Prim.Data.Shared.t }

      let[@inline] with_ data { f } =
        let (P access) = Access.current () in
        let data = Data.wrap ~access { shared = data } in
        let { many = { global = { aliased = data } } } =
          Prim.Password.with_current access (fun [@inline] password ->
            let password = Prim.Password.shared password in
            { many =
                Prim.Password.Shared.borrow password (fun [@inline] password ->
                  { global = { aliased = f { data; password } } })
            })
        in
        Prim.Data.Shared.unwrap ~access data
      ;;

      let[@inline] get { data; password } ~f =
        Prim.Data.Shared.map_into data ~password ~f:(fun [@inline] { shared } -> f shared)
        [@nontail]
      ;;

      let[@inline] map { data; password } ~f =
        { data =
            Prim.Data.map_shared data ~password ~f:(fun [@inline] { shared } ->
              { shared = f shared })
        ; password
        }
      ;;
    end

    let[@inline] with_ data ~f =
      let (P access) = Access.current () in
      let data = Data.wrap ~access { shared = data } in
      (Prim.Password.with_current access (fun [@inline] password ->
         let password = Prim.Password.shared password in
         { many =
             Prim.Password.Shared.borrow password (fun [@inline] password ->
               { global = { aliased = f (P { data; password }) } })
         }))
        .many
        .global
        .aliased
    ;;

    let[@inline] get (P t) ~f =
      (Prim.Data.Shared.project
         (Uncontended.get t ~f:(fun [@inline] a -> { portended = f a })))
        .portended
    ;;

    let iter = get
    let[@inline] map (P t) ~f = P (Uncontended.map t ~f)
  end
end
