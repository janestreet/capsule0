open! Import

(*_ NOTE: This is a low-level library for the implementation of capsules. Consider using
    [Capsule] (which is reexported by [Core]) instead, which is the intended entry-point
    for general users. *)

(** This module provides an interface to capsules that is a small subset of [Prim]
    (starting with the most common entry points) plus some useful higher-level types for
    common low-level capsule manipulation. The interface is also cleaned up to be somewhat
    easier to use, and more consistent with other conventions in [Base].

    This interface is currently directly exported via [Capsule]. Over time we will provide
    more of [Prim]'s functionality, and [Capsule] will add more in addition to
    [Extended]'s functionality. *)

module type Extended = sig @@ portable
  (** Capsules are a mechanism for safely having [uncontended] or [shared] access to
      mutable data from multiple threads.

      We consider every piece of mutable data in the program to live inside of some
      capsule. This might be an explicit capsule created using this interface, or an
      implicit capsule created when a new task is spawned (which expects a [portable]
      closure). Whenever a thread is executing a function, it has uncontended access to a
      single capsule - and any new mutable data it creates is created within that capsule.
      We say that the function is "running within" the capsule.

      Similarly, an implicit subcapsule is created when a subtask is forked (for example
      using {!Parallel.fork_join2}). Unlike capsules, a subcapsule is allowed to read
      mutable data from its parent, as expressed by the [shareable] (as opposed to
      [portable]) requirement over the subtask's closure.

      This module only provides interfaces that statically rule out data races. The
      [Await] and [Parallel] libraries augment capsules with various synchronization
      primitives that prevent data races dynamically. *)

  module Capsule := Prim

  (** [Access] defines an access token to inspect and use data within a capsule *)
  module Access : sig
    (** ['k t] represents access to the current capsule. An [uncontended] ['k t] indicates
        that ['k] is the current capsule. A [shared] ['k t] indicates that ['k] is the
        current capsule, but that it may be shared with other threads. A [contended]
        ['k t] indicates that ['k] might be some other capsule, and will thus grant no
        capabilities.

        ['k t]s cross portability, which means they can be shared with other threads.
        However, they do not cross contention, which means that ['k t]s captured in a
        [portable] closure become [contended], thus preventing any access to its data *)
    type 'k t = 'k Capsule.Access.t

    (** [packed] is the type of access to some unknown capsule. Unpacking one provides a
        ['k t] together with a fresh existential type brand for ['k]. *)
    type packed = Capsule.Access.packed = P : 'k t -> packed [@@unboxed]

    (** A boxed version of [Access.t] for places where you need a type with layout
        [value]. *)
    type 'k boxed = 'k Capsule.Access.boxed

    (** Obtain an [Access.t] for the current capsule. Since we do not know the brand for
        the current capsule, we receive a fresh one. *)
    val current : unit -> packed @@ portable

    val unbox : 'k boxed -> 'k t @@ portable
    val box : 'k t -> 'k boxed @@ portable
  end

  (** [Data] defines pointers to some data within a capsule *)
  module Data : sig
    (** [('a, 'k) t] represents a value of type ['a] that belongs to the capsule ['k]. It
        crosses both contention and portability, so can be freely passed to other threads.

        Its inner value may not be accessed directly. Instead, you can {!unwrap} it if you
        have an [uncontended] {!Access.t} token for the capsule. If you only want to
        access the immutable parts of its inner value, you can alternatively use
        {!get_id}. *)
    type ('a, 'k) t = ('a, 'k) Capsule.Data.t

    (** These functions are the most common way to interact with capsules. *)

    (** [create f] runs [f] within some capsule ['k], and returns a data point to the
        result. Since [f] can be run within an arbitrary capsule, it must be portable. As
        a result, [f] can't use data that might belong to another capsule, and isolation
        between capsules is maintained. If [f] produces a [unique] result, the resulting
        [Data.t] is unique. *)
    val%template create : (unit -> 'a @ u) @ local once portable -> ('a, 'k) t @ u
    [@@mode u = (unique, aliased)]

    [%%template:
    [@@@mode.default l = (global, local)]

    (** [wrap ~access v] adds [v] of some type ['a] to capsule ['k], and returns a
        [('a, 'k) Capsule.Data.t]. [~access] must be [uncontended], which means ['k] is
        always the current capsule. [v] itself must also be [uncontended], meaning it must
        have been created within the current capsule.

        [wrap] is templated over locality, which means that if you only have access to [v]
        locally, you can create a [local] data value; use
        {[
          Capsule.Data.wrap [@mode local]
        ]}
        to use the version that accepts a local value [v] and produces a [local]
        {!Capsule.Data.t}. *)
    val wrap : access:'k Access.t -> 'a @ l -> ('a, 'k) t @ l

    (** [unwrap ~access t] returns the value of [t], which lives in the capsule ['k].
        [~access] is either [uncontended] or [shared], which means that ['k] is always the
        current capsule.

        If [~access] is [uncontended], we have sole access to the capsule ['k], and it is
        safe to access the value of [t] as [uncontended].

        If [~access] is [shared], other threads might have simultaneous [shared] access to
        ['k], and access to the value of [t] is limited to [shared], and must cross
        [portable].

        [unwrap] is templated over locality, which means that a [local] {!Capsule.Data.t}
        will grant you a [local] value. *)
    val unwrap
      : ('a : value mod p) 'k.
      access:'k Access.t @ c -> ('a, 'k) t @ l -> 'a @ c l
    [@@mode l = l, (c, p) = ((uncontended, nonportable), (shared, portable))]

    (** These functions enable more complicated manipulation of capsules. *)

    (** [return v] creates a pointer to a value [v] injected into the capsule ['k]. The
        value must cross contention and be portable, since it is being moved from the
        current capsule into the capsule ['k]. *)
    val return : ('a : value mod contended) @ l portable -> ('a, 'k) t @ l

    (** [both t1 t2] is a pointer to a pair of the values of [t1] and [t2]. *)
    val both : ('a, 'k) t @ l -> ('b, 'k) t @ l -> ('a * 'b, 'k) t @ l

    (** [fst t] gives a pointer to the first value inside [t] *)
    val fst : ('a * _, 'k) t @ l -> ('a, 'k) t @ l

    (** [snd t] gives a pointer to the second value inside [t] *)
    val snd : (_ * 'b, 'k) t @ l -> ('b, 'k) t @ l

    (** [get_id t] retrieves the value of [t] directly. The result is a value within ['k],
        which is not guaranteed to be the current capsule. As such, it is marked as
        [contended], and must always be [portable]. Likely only useful if the capsule has
        already been [map]'d, as capsules do not usually contain portable values. *)
    val get_id : ('a : value mod portable) 'k. ('a, 'k) t @ l -> 'a @ contended l]

    [%%template:
      val idx : ('a, 'k) t @ l -> ('a, 'b) idx_imm -> ('b, 'k) t @ l
      [@@ocaml.doc
        {| [idx t i] is a pointer to the value at [i] in [t].

          See {!Ox.Idx} for more information on indexes. |}]
      [@@mode l = (global, local)]]
  end

  (** Meaningful access to the value within a [('a, 'k) Data.t] pointer requires an
      [uncontended] or [shared] ['k Access.t]. An ['k Access.t] can be synchronized using
      [Sync.Mutex.with_lock] from the [Await] library.

      Alternatively, the three following modules [Frozen], [Owned] and [Scoped] offer
      practical wrappers for common patterns when synchronizing capsule access.

      [Frozen] represents a capsule whose contents have been permanently frozen: nobody
      may write to it, so everyone may read from it without synchronization.

      [Owned] uses aliasing as a proxy for contention; owning a capsule uniquely is
      sufficient to access a capsule, since uniqueness guarantees that only one thread has
      access to it.

      [Scoped] uses ['k Capsule.Password.t] -- a token that is only ever available locally
      -- to grant permission for the current thread to have [uncontended] access to the
      capsule ['k] for the duration of the current region. Locality guarantees that a
      password is not shared with other existing threads. Unlike [Owned] and the more
      direct [Access.t], a [Scoped.t] crosses contention, and can hence be accessed from a
      different capsule.

      A [Scoped.Shared] represents a temporary freeze: the capsule may only be read from
      for the duration of the local ['k Capsule.Password.Shared.t]

      Each wrapper offers various trade-offs; when making a choice over which kind of
      wrapper to use, it can be useful to observe whether a piece of data follows a common
      pattern:
      - Does the data go through a phase where it gets initialized, after which it is only
        read from by multiple threads? You can create a [Frozen] using {!Frozen.create}.
      - Is it necessary to acquire locks for multiple capsules at the same time? A
        [Scoped] must be used.
      - Are you trying to access some immutable part of your data? You do not need to
        acquire access to a capsule, you can use [Data.get_id].

      [Frozen], [Owned] and [Scoped] can each be synchronized with a mutex or
      reader-writer lock in the {!Await} or {!Parallel} libraries *)

  module Isolated : sig
    (** The underlying representation of both [Frozen.t] and [Owned.t]. *)
    module Repr : sig
      type ('a, 'k) inner =
        #{ data : ('a, 'k) Data.t
         ; key : 'k Capsule.Key.t
         }

      type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]
    end
  end

  module%template Frozen : sig
    (** A frozen value in its own capsule. Nobody may write to the contained ['a] without
        synchronization, so everyone may read from it.

        This type is useful for locally initializing some mutable data structure, then
        permanently freezing it to give read access to multiple threads.

        Note that types which are [sync_data], such as atomic references, may still be
        mutated when stored in a [Capsule.Frozen.t]. *)
    type 'a
         t :
         value
         mod contended forkable many portable unyielding
         with 'a portable @@ contended portable

    [@@@mode.default l = (global, local)]

    val to_repr : 'a t @ l -> 'a portable Isolated.Repr.t @ l
    val of_repr : 'a portable Isolated.Repr.t @ l -> 'a t @ l

    (** [create f] runs [f] within a fresh capsule, and creates a [Capsule.Frozen.t]
        containing the result. *)
    val create : (unit -> 'a @ l portable) @ local once portable -> 'a t @ l

    (** [unwrap t] takes a frozen capsule [t] and returns the underlying value at
        [shared]. *)
    val unwrap : 'a t @ l -> 'a @ l portable shared
  end

  module%template Owned : sig
    (** A capsule that uses [unique]ness tracking to enable different threads to gain
        [uncontended] access to its contents at different times without need for runtime
        synchronization. *)
    type 'a
         t :
         value
         mod contended forkable many portable unyielding
         with 'a @@ contended portable

    [@@@mode.default l = (global, local)]

    val to_repr : 'a t @ l unique -> 'a Isolated.Repr.t @ l unique
    val of_repr : 'a Isolated.Repr.t @ l unique -> 'a t @ l unique

    (** [create f] runs [f] within a fresh capsule, and creates a [Capsule.Owned.t]
        containing the result. *)
    val create : (unit -> 'a @ l unique) @ local once portable -> 'a t @ l unique

    (** [freeze t] takes an [aliased] owned capsule (which can no longer be written to
        since it isn't [unique]) and converts it to a {!Frozen.t}. *)
    val freeze : ('a : value mod portable). 'a t @ l -> 'a Frozen.t @ l

    (** [unwrap t] consumes a [unique] isolated capsule [t] and returns the underlying
        value, merging the capsule with the current capsule. *)
    val unwrap : 'a t @ l unique -> 'a @ l unique

    (** Project out a contended reference to the underlying value from a unique [t],
        returning the unique [t] back alongside the alias to the underlying value. *)
    val get_contended
      : ('a : value mod aliased portable).
      'a t @ l unique -> #('a t * 'a) @ contended l unique

    (** [with_ t ~f] takes a [unique] isolated capsule [t], calls [f] with its value, and
        returns a tuple of the unique isolated capsule and the result of [f]. *)
    val with_
      : ('a : value mod aliased) ('b : value mod contended portable).
      'a t @ l unique
      -> f:('a @ l -> 'b @ l unique) @ local once portable
      -> #('a t * 'b) @ l unique
  end

  module Scoped : sig
    type ('a, 'k) inner =
      #{ data : ('a, 'k) Data.t @@ global
       ; password : 'k Capsule.Password.t
       }

    (** An encapsulated value accessible for the duration of the current region.

        A value of type ['a Scoped.t] provides [uncontended] access to the underlying ['a]
        over a local scope. *)
    type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]

    (** [with_ a ~f] calls [f] with a [local] {!Scoped.t} representing local access to
        [a], which lives in the current capsule. *)
    val with_ : 'a -> f:('a t @ local -> 'b) @ local once -> 'b

    (** [get t ~f] computes a value using the data accessible via [t]. *)
    val get
      :  'a t @ local
      -> f:('a -> 'b @ contended portable) @ local once portable
      -> 'b @ contended portable

    (** Like [get], but for for functions that return [unit]. *)
    val iter : 'a t @ local -> f:('a -> unit) @ local once portable -> unit

    (** Construct a new [t] by mapping a function over the referenced value. *)
    val map : 'a t @ local -> f:('a -> 'b) @ local once portable -> 'b t @ local

    module Shared : sig
      type ('a, 'k) inner =
        #{ data : ('a shared, 'k) Data.t @@ global
         ; password : 'k Capsule.Password.Shared.t
         }

      (** An encapsulated value that may be read for the duration of the current region.

          A value of type ['a Scoped.Shared.t] provides [shared] access to the underlying
          ['a] over a local scope. A [forkable] ['a Scoped.Shared.t] can be captured by
          functions that run from other capsules. *)
      type 'a t = P : ('a, 'k) inner -> 'a t [@@unboxed]

      (** [with_ a ~f] calls [f] with a [local forkable] {!Shared.t} representing local
          read-only access to [a], which is readable in the current capsule. *)
      val with_
        : ('a : value mod portable) 'b.
        'a @ shared -> f:('a t @ forkable local -> 'b) @ forkable local once -> 'b

      (** [get t ~f] computes a value using data accessible via [t]. *)
      val get
        : ('a : value mod portable) 'b.
        'a t @ local
        -> f:('a @ shared -> 'b @ contended portable) @ local once portable
        -> 'b @ contended portable

      (** Like [get], but for for functions that return [unit]. *)
      val iter
        : ('a : value mod portable).
        'a t @ local -> f:('a @ shared -> unit) @ local once portable -> unit

      (** Construct a new [t] by mapping a function over the referenced value. *)
      val map
        : ('a : value mod portable) ('b : value mod portable).
        'a t @ local
        -> f:('a @ shared -> 'b @ shared) @ local once portable
        -> 'b t @ local

      module Uncontended : sig
        (** Like ['a Scoped.Shared.t], but allows read-only computations to return an
            uncontended result in the current capsule. *)
        type ('a, 'k) t = ('a, 'k) inner =
          #{ data : ('a shared, 'k) Data.t @@ global
           ; password : 'k Capsule.Password.Shared.t
           }

        type ('a, 'b) f =
          { f : 'k. ('a, 'k) t @ forkable local -> ('b, 'k) Capsule.Data.Shared.t }

        (** [with_ a ~f] calls [f] with a [local forkable] {!Scoped.Shared.Uncontended.t}
            representing local read-only access to [a], which is readable in the current
            capsule.

            The result of [f] is a [Capsule.Data.Shared.t], which can be unwrapped in the
            current capsule. *)
        val with_ : 'a @ shared -> ('a, 'b) f @ forkable local once -> 'b

        (** [get t ~f] computes a value using data accessible via [t]. *)
        val get
          : ('a : value mod portable) 'b 'k.
          ('a, 'k) t @ local
          -> f:('a @ shared -> 'b) @ local once portable
          -> ('b, 'k) Capsule.Data.Shared.t

        (** Construct a new [t] by mapping a function over the referenced value. *)
        val map
          : ('a : value mod portable) ('b : value mod portable) 'k.
          ('a, 'k) t @ local
          -> f:('a @ shared -> 'b @ shared) @ local once portable
          -> ('b, 'k) t @ local
      end
    end
  end

  module (Initial @@ nonportable) : sig
    (** The initial capsule is the implicit capsule associated with the OCaml top level.
        Since this is the capsule in which library top-levels run, any [nonportable]
        top-level function belongs to the initial capsule, and hence is allowed to access
        it. *)

    (** The brand for the initial capsule. *)
    type k = Capsule.initial

    (** Access to the initial capsule *)
    val access : k Access.t

    module Data : sig
      (** A value in the initial capsule. *)
      type 'a t = ('a, k) Data.t

      val t_of_sexp : (Sexp.t -> 'a) -> Sexp.t -> 'a t
      val sexp_of_t : ('a -> Sexp.t) -> 'a t -> Sexp.t

      [%%template:
      [@@@mode.default l = (global, local)]

      (** Store a value in a [Capsule.Data.t] for the initial capsule. This function is
          [nonportable], requiring it to only be run from the initial capsule. *)
      val wrap : 'a @ l -> 'a t @ l

      (** Extract a value from a [Capsule.Data.t] for the initial capsule. This function
          is [nonportable], requiring it to only be run from the initial capsule. *)
      val unwrap : 'a t @ l -> 'a @ l]
    end
  end
end
